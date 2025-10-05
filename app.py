# app.py — ANWW Duikapp (username + wachtwoord) • Build v2025-10-05
# Functies:
# - Login met username/password + rol (admin/user/member/viewer)
# - Login-logo (beheerder kan uploaden; bewaard in Storage + app_settings)
# - Activiteiten (sort vroeg→laat), inschrijven met opmerking, optioneel Volw/Kind, maaltijdkeuze (max 3)
# - Locatie uit duikplaatsen (admin kan loc toevoegen)
# - CSV export per activiteit, verwijderen (admin)
# - Weekmail preview/export (neemt V/K mee indien enable_counts)

import streamlit as st
import pandas as pd
import datetime
from datetime import datetime as dt
import io
import hmac, hashlib
from supabase import create_client, Client
from postgrest.exceptions import APIError

# ──────────────────────────────────────────────────────────────────────────────
# UI CONFIG + CSS
# ──────────────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="ANWW Duikapp", layout="wide")
APP_BUILD = "v2025-10-05"

def inject_css():
    st.markdown("""
    <style>
      :root {
        --bg: #8DAEBA;       /* achtergrond */
        --panel: #A38B16;    /* panelen/tabs */
        --text: #11064D;     /* tekst */
        --primary: #728DCC;  /* knoppen */
        --border: #2a355a;
        --success: #3CA133; --warning: #f59e0b; --error: #ef4444;
      }
      .stApp, [data-testid="stAppViewContainer"], .main, div.block-container {
        background-color: var(--bg) !important; color: var(--text) !important;
      }
      .stButton > button, .stDownloadButton > button {
        background-color: var(--primary) !important; color:#fff !important;
        border: 2px solid var(--border) !important; border-radius: 10px !important;
        padding:.45em 1.1em !important; font-weight:600 !important;
      }
      .center-wrap { display:flex; justify-content:center; }
      .muted { opacity:.75; font-style:italic; }
      .tiny { font-size:.9em; opacity:.8; }
    </style>
    """, unsafe_allow_html=True)

inject_css()

# ──────────────────────────────────────────────────────────────────────────────
# SUPABASE CLIENT
# ──────────────────────────────────────────────────────────────────────────────
@st.cache_resource(show_spinner=False)
def get_client() -> Client:
    url = st.secrets["supabase"]["url"]
    key = st.secrets["supabase"]["anon_key"]
    return create_client(url, key)

sb: Client = get_client()

def run_db(fn, what=""):
    try:
        return fn(sb)
    except APIError as e:
        st.error(f"API-fout bij {what}. Controleer tabellen/policy/RLS ({e.code}).")
        raise
    except Exception as e:
        st.error(f"Fout bij {what}: {e}")
        raise

# ──────────────────────────────────────────────────────────────────────────────
# HELPERS: AUTH / SETTINGS
# ──────────────────────────────────────────────────────────────────────────────
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def auth_check(username: str, password: str):
    """Controleer gebruiker in tabel 'users' (velden: username, password_hash, role)."""
    res = run_db(lambda c: c.table("users").select("username,password_hash,role").eq("username", username).single().execute(),
                 what="users select (login)")
    if not res.data: return None
    ph = (res.data or {}).get("password_hash") or ""
    ok = (ph == sha256_hex(password)) or (ph == password)  # fallback voor legacy plain
    if not ok: return None
    return {"username": res.data["username"], "role": (res.data.get("role") or "viewer")}

def require_role(*roles):
    r = st.session_state.get("role")
    if r not in roles:
        st.warning("Je hebt geen toegang tot deze pagina.")
        st.stop()

def current_username(): return st.session_state.get("username")
def current_role(): return st.session_state.get("role","viewer")

# app settings (logo)
def settings_get(key: str) -> str | None:
    res = run_db(lambda c: c.table("app_settings").select("value").eq("key", key).maybe_single().execute(),
                 what=f"app_settings get {key}")
    if not res.data: return None
    return res.data.get("value")

def settings_set(key: str, value: str | None):
    payload = {"key": key, "value": value}
    run_db(lambda c: c.table("app_settings").upsert(payload, on_conflict="key").execute(),
           what=f"app_settings set {key}")

# ──────────────────────────────────────────────────────────────────────────────
# HELPERS: DATA (duikplaatsen / activiteiten / signups)
# ──────────────────────────────────────────────────────────────────────────────
def plaatsen_list() -> list[str]:
    res = run_db(lambda c: c.table("duikplaatsen").select("name").order("name").execute(),
                 what="duikplaatsen select")
    return [r["name"] for r in (res.data or [])]

def plaats_add(name: str):
    run_db(lambda c: c.table("duikplaatsen").insert({"name": name}).execute(),
           what="duikplaats insert")

def activiteit_add(titel, omschr, datum, tijd, locatie, meal_opts, created_by, enable_counts: bool = False):
    payload = {
        "titel": titel,
        "omschrijving": omschr or None,
        "datum": datum.isoformat() if hasattr(datum, "isoformat") else datum,
        "tijd": tijd.strftime("%H:%M") if tijd else None,
        "locatie": locatie or None,
        "meal_options": meal_opts or None,
        "created_by": created_by or None,
        "enable_counts": bool(enable_counts),
    }
    run_db(lambda c: c.table("activiteiten").insert(payload).execute(), what="activiteit insert")

def activiteiten_df(upcoming=True) -> pd.DataFrame:
    q = sb.table("activiteiten").select("*")
    today = datetime.date.today().isoformat()
    if upcoming: q = q.gte("datum", today)
    q = q.order("datum", desc=False).order("tijd", desc=False)
    res = run_db(lambda c=q: c.execute(), what="activiteiten select")
    return pd.DataFrame(res.data or [])

def activiteiten_delete(ids: list[str]):
    if not ids: return
    run_db(lambda c: c.table("activiteiten").delete().in_("id", ids).execute(),
           what="activiteiten delete")

def signups_get(activiteit_id) -> pd.DataFrame:
    res = run_db(lambda c: c.table("activity_signups").select("*").eq("activiteit_id", activiteit_id).execute(),
                 what="signups select")
    return pd.DataFrame(res.data or [])

def signup_upsert(activiteit_id, username, status, eating=None, meal_choice=None,
                  comment: str | None = None, adults: int | None = None, children: int | None = None):
    if status not in ("yes", "no"):
        raise ValueError("status moet 'yes' of 'no' zijn")
    payload = {
        "activiteit_id": activiteit_id,
        "username": username,
        "status": status,
        "eating": eating if status == "yes" else None,
        "meal_choice": meal_choice if (status == "yes" and meal_choice) else None,
        "comment": (comment or None),
        "adults": int(adults) if (adults is not None) else None,
        "children": int(children) if (children is not None) else None,
    }
    run_db(lambda c: c.table("activity_signups")
           .upsert(payload, on_conflict="activiteit_id,username").execute(),
           what="signup upsert")

# ──────────────────────────────────────────────────────────────────────────────
# LOGIN + LOGO
# ──────────────────────────────────────────────────────────────────────────────
def login_page():
    st.title("Aanmelden")
    # logo tonen (indien ingesteld)
    logo_url = settings_get("login_logo_url")
    if logo_url:
        st.markdown(f'<div class="center-wrap"><img src="{logo_url}" style="max-height:120px;border-radius:12px" /></div>', unsafe_allow_html=True)
        st.write("")

    with st.form("login_form"):
        u = st.text_input("Gebruikersnaam")
        p = st.text_input("Wachtwoord", type="password")
        ok = st.form_submit_button("Inloggen", type="primary")
        if ok:
            user = auth_check(u.strip(), p)
            if not user:
                st.error("Onjuiste inloggegevens.")
            else:
                st.session_state["username"] = user["username"]
                st.session_state["role"] = user["role"]
                st.success(f"Ingelogd als {user['username']} ({user['role']}).")
                st.rerun()

    st.caption(f"Build: {APP_BUILD}")

def page_settings():
    require_role("admin")
    st.header("Beheerinstellingen")
    st.subheader("Login-logo")
    logo_url = settings_get("login_logo_url")
    if logo_url:
        st.image(logo_url, caption="Huidig logo", width=220)
    f = st.file_uploader("Upload nieuw logo (JPG/PNG)", type=["jpg","jpeg","png"])
    if f and st.button("Logo opslaan", type="primary"):
        # upload naar Supabase Storage (bucket 'assets', object 'login_logo.jpg')
        data = f.read()
        try:
            # verwijder event. bestaande
            try:
                sb.storage.from_("assets").remove(["login_logo.jpg"])
            except Exception:
                pass
            sb.storage.from_("assets").upload("login_logo.jpg", data, {"content-type": f"type/{f.name.split('.')[-1]}"})
            # maak public URL
            pub = sb.storage.from_("assets").get_public_url("login_logo.jpg")
            settings_set("login_logo_url", pub)
            st.success("Logo opgeslagen.")
            st.rerun()
        except Exception as e:
            st.error(f"Opslaan mislukt: {e}")

# ──────────────────────────────────────────────────────────────────────────────
# ACTIVITEITEN
# ──────────────────────────────────────────────────────────────────────────────
def page_activiteiten():
    st.header("Kalender & Inschrijvingen")

    # ADMIN: nieuwe activiteit
    if current_role() == "admin":
        with st.expander("➕ Nieuwe activiteit"):
            c1, c2 = st.columns([2,1])
            with c1:
                titel = st.text_input("Titel*")
                omschr = st.text_area("Omschrijving")
            with c2:
                datum = st.date_input("Datum*", value=datetime.date.today())
                tijd = st.time_input("Tijd (optioneel)", value=None)
                # locatie uit duikplaatsen
                pl = plaatsen_list()
                locatie = st.selectbox("Locatie", ["— kies —"] + pl, index=0, key="act_loc_select")
                new_loc = st.text_input("Nieuwe locatie (indien niet in lijst)", key="act_new_loc")
                if st.button("➕ Locatie toevoegen", key="act_add_loc_btn"):
                    if new_loc and new_loc not in pl:
                        try:
                            plaats_add(new_loc)
                            st.success("Locatie toegevoegd. Kies nu uit de lijst.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Mislukt: {e}")
                    else:
                        st.warning("Leeg of al bestaand.")

            st.caption("Maaltijdopties (max. 3, optioneel)")
            m1, m2, m3 = st.columns(3)
            with m1: mo1 = st.text_input("Optie 1", key="act_meal1")
            with m2: mo2 = st.text_input("Optie 2", key="act_meal2")
            with m3: mo3 = st.text_input("Optie 3", key="act_meal3")

            ask_counts = st.checkbox("Inschrijvers laten aangeven: # Volwassenen / # Kinderen", value=False, key="act_enable_counts")

            if st.button("Activiteit toevoegen", type="primary", key="act_add_btn"):
                if not titel or not datum:
                    st.warning("Titel en datum zijn verplicht.")
                else:
                    meal_opts = [x.strip() for x in [mo1, mo2, mo3] if x and x.strip()]
                    try:
                        activiteit_add(
                            titel=titel, omschr=omschr, datum=datum, tijd=tijd,
                            locatie=None if not locatie or locatie == "— kies —" else locatie.strip(),
                            meal_opts=meal_opts or None,
                            created_by=current_username(),
                            enable_counts=ask_counts
                        )
                        st.success("Activiteit aangemaakt.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Mislukt: {e}")

    # Lijst activiteiten (vroeg -> laat)
    df = activiteiten_df(upcoming=True)
    if df.empty:
        st.info("Geen (toekomstige) activiteiten.")
        return

    df = df.sort_values(["datum","tijd"], na_position="last").reset_index(drop=True)

    user = current_username()
    role = current_role()

    # Lijst (één regel per activiteit + telletjes achteraan)
    for i, row in df.iterrows():
        rid = str(row.get("id") or f"idx{i}")
        s = signups_get(row["id"])

        # totals
        if bool(row.get("enable_counts")):
            yes_adults = int(s.loc[s["status"]=="yes", "adults"].fillna(0).astype(int).sum()) if not s.empty else 0
            yes_children = int(s.loc[s["status"]=="yes", "children"].fillna(0).astype(int).sum()) if not s.empty else 0
            no_cnt = int((s["status"]=="no").sum()) if not s.empty else 0
            tellers_txt = f"<small class='muted'>(V: {yes_adults} · K: {yes_children} · niet: {no_cnt})</small>"
        else:
            yes_cnt = int((s["status"]=="yes").sum()) if not s.empty else 0
            no_cnt = int((s["status"]=="no").sum()) if not s.empty else 0
            tellers_txt = f"<small class='muted'>({yes_cnt} komen · {no_cnt} niet)</small>"

        # my status
        myrow = s.loc[s["username"] == user] if (user and not s.empty) else pd.DataFrame()
        my_status = myrow.iloc[0]["status"] if not myrow.empty else None
        badge = "🟢" if my_status == "yes" else ("🔴" if my_status == "no" else "⚪")

        # regelkop
        datum_str = pd.to_datetime(row["datum"]).strftime("%d/%m/%Y")
        tijd_str = f" · {row['tijd']}" if row.get("tijd") else ""
        titel = f"{datum_str}{tijd_str} — {row['titel']}"
        loc_str = f" · 📍 {row['locatie']}" if row.get("locatie") else ""
        st.markdown(f"**{titel}{loc_str}**  {badge} &nbsp;&nbsp; {tellers_txt}", unsafe_allow_html=True)

        with st.expander("Inschrijven / details", expanded=False):
            if row.get("omschrijving"):
                st.write(row["omschrijving"])

            coming = s.loc[s["status"]=="yes"].sort_values("signup_ts")
            notcoming = s.loc[s["status"]=="no"].sort_values("signup_ts")

            colA, colB = st.columns(2)
            with colA:
                st.markdown("**Komen (op volgorde van inschrijving):**")
                if coming.empty:
                    st.caption("Nog niemand.")
                else:
                    for _, ss in coming.iterrows():
                        meal = f" · eet: {ss['meal_choice']}" if ss.get("eating") else ""
                        extra = ""
                        if bool(row.get("enable_counts")):
                            va = int(ss.get("adults") or 0)
                            vk = int(ss.get("children") or 0)
                            extra = f" · (V:{va}, K:{vk})" if (va or vk) else ""
                        st.write(f"- {ss.get('username') or 'lid'}{meal}{extra}")

            with colB:
                st.markdown("**Niet komen:**")
                if notcoming.empty:
                    st.caption("Nog niemand.")
                else:
                    for _, ss in notcoming.iterrows():
                        st.write(f"- {ss.get('username') or 'lid'}")

            # Inschrijven (rollen admin/user/member)
            if role in {"admin","user","member"}:
                st.divider()
                st.markdown("**Mijn inschrijving**")

                prev = myrow.iloc[0] if not myrow.empty else {}
                prev_eating = bool(prev.get("eating")) if prev else False
                prev_meal = prev.get("meal_choice") if prev else None
                prev_comment = prev.get("comment") if prev else ""
                prev_adults = int(prev.get("adults") or 1)
                prev_children = int(prev.get("children") or 0)

                init_index = 0 if my_status in (None, "yes") else 1
                status_choice = st.radio("Status", ["Ik kom", "Ik kom niet"], horizontal=True,
                                         index=init_index, key=f"act_{rid}_status")

                comment_val = st.text_area("Opmerking (optioneel)", value=prev_comment, key=f"act_{rid}_comment")

                eating = None; meal_choice = None; adults_val = None; children_val = None
                meal_opts = row.get("meal_options") or []

                if status_choice == "Ik kom":
                    eating = st.checkbox("Ik eet mee", value=prev_eating, key=f"act_{rid}_eat")
                    if eating and meal_opts:
                        default_ix = 0
                        if prev_meal and prev_meal in meal_opts:
                            default_ix = (meal_opts.index(prev_meal) + 1)
                        mc = st.selectbox("Kies je maaltijd", ["— kies —"] + meal_opts, index=default_ix, key=f"act_{rid}_meal")
                        meal_choice = None if mc == "— kies —" else mc

                    if bool(row.get("enable_counts")):
                        ca, cb = st.columns(2)
                        with ca:
                            adults_val = st.number_input("Volwassenen", min_value=0, max_value=50, step=1,
                                                         value=max(1, prev_adults), key=f"act_{rid}_adults")
                        with cb:
                            children_val = st.number_input("Kinderen", min_value=0, max_value=50, step=1,
                                                          value=max(0, prev_children), key=f"act_{rid}_children")

                if st.button("Bewaar mijn keuze", key=f"act_{rid}_save", type="primary"):
                    try:
                        signup_upsert(
                            activiteit_id=row["id"],
                            username=user,
                            status=("yes" if status_choice == "Ik kom" else "no"),
                            eating=eating,
                            meal_choice=meal_choice,
                            comment=comment_val,
                            adults=adults_val,
                            children=children_val
                        )
                        st.success("Inschrijving bijgewerkt."); st.rerun()
                    except Exception as e:
                        st.error(f"Opslaan mislukt: {e}")

            # Export / print
            st.markdown("---")
            st.markdown("**Afdruk / export inschrijvingen**")
            cols = ["username","status","eating","meal_choice","adults","children","comment","signup_ts"]
            cols = [c for c in cols if c in s.columns]
            print_df = s[cols].copy()
            print_df = print_df.rename(columns={
                "username":"Gebruiker","status":"Status","eating":"Eet mee",
                "meal_choice":"Maaltijd","adults":"Volw","children":"Kind","comment":"Opmerking",
                "signup_ts":"Ingeschreven op"
            })
            if not print_df.empty and "Ingeschreven op" in print_df.columns:
                print_df["Ingeschreven op"] = pd.to_datetime(print_df["Ingeschreven op"]).dt.strftime("%d/%m/%Y %H:%M")
            st.dataframe(print_df, use_container_width=True, hide_index=True)
            buf = io.BytesIO(); print_df.to_csv(buf, index=False)
            st.download_button("⬇️ Download CSV", data=buf.getvalue(),
                               file_name=f"inschrijvingen_{row['titel']}_{row['datum']}.csv",
                               mime="text/csv", key=f"act_{rid}_csv")

    # ADMIN: verwijderen + weekmail
    if role == "admin":
        st.divider()
        st.subheader("Activiteiten verwijderen")
        options, id_map = [], {}
        for _, r in df.iterrows():
            datum_str = pd.to_datetime(r["datum"]).strftime("%d/%m/%Y")
            tijd_str = f" · {r['tijd']}" if r.get("tijd") else ""
            loc_str = f" · {r['locatie']}" if r.get("locatie") else ""
            label = f"{datum_str}{tijd_str} · {r['titel']}{loc_str}"
            options.append(label); id_map[label] = r["id"]
        sel_labels = st.multiselect("Selecteer activiteiten", options, key="del_act_sel_admin")
        if st.button("Verwijder geselecteerde activiteiten", key="del_act_btn_admin", type="primary",
                     disabled=not sel_labels):
            try:
                ids = [id_map[lbl] for lbl in sel_labels if lbl in id_map]
                activiteiten_delete(ids)
                st.success(f"Verwijderd: {len(ids)} activiteit(en)."); st.rerun()
            except Exception as e:
                st.error(f"Verwijderen mislukt: {e}")

    st.divider()
    st.subheader("Wekelijkse mail — eerstvolgende 4")
    # Bouw een samenvatting die V/K meeneemt als enable_counts actief is
    mail_df = df.head(4).copy()
    rows = []
    for _, r in mail_df.iterrows():
        s = signups_get(r["id"])
        if bool(r.get("enable_counts")):
            volw = int(s.loc[s["status"]=="yes", "adults"].fillna(0).astype(int).sum()) if not s.empty else 0
            kind = int(s.loc[s["status"]=="yes", "children"].fillna(0).astype(int).sum()) if not s.empty else 0
            niet = int((s["status"]=="no").sum()) if not s.empty else 0
            teller = f"V:{volw} · K:{kind} · niet:{niet}"
        else:
            yes = int((s["status"]=="yes").sum()) if not s.empty else 0
            no  = int((s["status"]=="no").sum())  if not s.empty else 0
            teller = f"{yes} komen · {no} niet"
        rows.append({
            "Titel": r["titel"],
            "Datum": pd.to_datetime(r["datum"]).strftime("%d/%m/%Y"),
            "Tijd": r.get("tijd") or "",
            "Locatie": r.get("locatie") or "",
            "Teller": teller
        })
    if rows:
        view = pd.DataFrame(rows)
        st.dataframe(view, use_container_width=True, hide_index=True)
        out = io.BytesIO(); view.to_csv(out, index=False)
        st.download_button("⬇️ Exporteer weekmail CSV", data=out.getvalue(),
                           file_name="weekmail_activiteiten.csv", mime="text/csv")

# ──────────────────────────────────────────────────────────────────────────────
# APP
# ──────────────────────────────────────────────────────────────────────────────
def main():
    st.sidebar.title("ANWW")
    if "username" not in st.session_state:
        login_page()
        return

    st.sidebar.markdown(f"**Ingelogd als:** {current_username()} ({current_role()})")
    if st.sidebar.button("Uitloggen"):
        st.session_state.clear(); st.rerun()

    tabs = st.tabs(["Kalender", "Beheerinstellingen"])
    with tabs[0]:
        page_activiteiten()
    with tabs[1]:
        if current_role() == "admin":
            page_settings()
        else:
            st.info("Alleen voor beheerders.")

if __name__ == "__main__":
    main()

