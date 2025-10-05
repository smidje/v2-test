# app.py — ANWW Duikapp (username + wachtwoord) • Build v2025-10-05 • STABIEL BASIS
# Functies:
# - Login (username/password) + rol (admin/user/member/viewer)
# - Kleuren-CSS
# - Activiteiten (sort: vroeg→laat), inschrijven (Ik kom / Ik kom niet), optionele maaltijdkeuze (max 3)
# - Locatie uit duikplaatsen (admin kan toevoegen)
# - CSV export per activiteit
# - Verwijderen van activiteiten (admin)
# - Weekmail preview/export (eerstvolgende 4)

import streamlit as st
import pandas as pd
import datetime
import io
import hashlib
from supabase import create_client, Client
from postgrest.exceptions import APIError

# ──────────────────────────────────────────────────────────────────────────────
# UI CONFIG + CSS
# ──────────────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="ANWW Duikapp", layout="wide")
APP_BUILD = "v2025-10-05-stable-base"

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
      .muted { opacity:.8; font-style:italic; }
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
# AUTH
# ──────────────────────────────────────────────────────────────────────────────
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def auth_check(username: str, password: str):
    res = run_db(lambda c: c.table("users").select("username,password_hash,role")
                 .eq("username", username).maybe_single().execute(),
                 what="users select (login)")
    if not res.data:
        return None
    ph = (res.data or {}).get("password_hash") or ""
    ok = (ph == sha256_hex(password)) or (ph == password)  # fallback voor legacy plain
    if not ok:
        return None
    return {"username": res.data["username"], "role": (res.data.get("role") or "viewer")}

def current_username(): return st.session_state.get("username")
def current_role(): return st.session_state.get("role","viewer")

# ──────────────────────────────────────────────────────────────────────────────
# DATA HELPERS
# ──────────────────────────────────────────────────────────────────────────────
def plaatsen_list() -> list[str]:
    res = run_db(lambda c: c.table("duikplaatsen").select("name").order("name").execute(),
                 what="duikplaatsen select")
    return [r["name"] for r in (res.data or [])]

def plaats_add(name: str):
    run_db(lambda c: c.table("duikplaatsen").insert({"name": name}).execute(),
           what="duikplaats insert")

def activiteit_add(titel, omschr, datum, tijd, locatie, meal_opts, created_by):
    payload = {
        "titel": titel,
        "omschrijving": omschr or None,
        "datum": datum.isoformat() if hasattr(datum, "isoformat") else datum,
        "tijd": tijd.strftime("%H:%M") if tijd else None,
        "locatie": locatie or None,
        "meal_options": meal_opts or None,
        "created_by": created_by or None,
    }
    run_db(lambda c: c.table("activiteiten").insert(payload).execute(), what="activiteit insert")

def activiteiten_df(upcoming=True) -> pd.DataFrame:
    q = sb.table("activiteiten").select("*")
    if upcoming:
        q = q.gte("datum", datetime.date.today().isoformat())
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

def signup_upsert(activiteit_id, username, status, eating=None, meal_choice=None):
    if status not in ("yes", "no"):
        raise ValueError("status moet 'yes' of 'no' zijn")
    payload = {
        "activiteit_id": activiteit_id,
        "username": username,
        "status": status,
        "eating": eating if status == "yes" else None,
        "meal_choice": meal_choice if (status == "yes" and meal_choice) else None,
    }
    run_db(lambda c: c.table("activity_signups")
           .upsert(payload, on_conflict="activiteit_id,username").execute(),
           what="signup upsert")

# ──────────────────────────────────────────────────────────────────────────────
# LOGIN
# ──────────────────────────────────────────────────────────────────────────────
def login_page():
    st.title("Aanmelden")
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
                tijd = st.time_input("Tijd (optioneel)", value=datetime.time(9, 0))
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
                            created_by=current_username()
                        )
                        st.success("Activiteit aangemaakt."); st.rerun()
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

    # Lijst (één regel per activiteit + tellers achteraan)
    for i, row in df.iterrows():
        rid = str(row.get("id") or f"idx{i}")
        s = signups_get(row["id"])

        # totals (alleen aantal inschrijvingen; geen V/K)
        yes_cnt = int((s["status"]=="yes").sum()) if not s.empty else 0
        no_cnt  = int((s["status"]=="no").sum())  if not s.empty else 0
        tellers_txt = f"<small class='muted'>({yes_cnt} komen · {no_cnt} niet)</small>"

        # mijn status
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
                        st.write(f"- {ss.get('username') or 'lid'}{meal}")
            with colB:
                st.markdown("**Niet komen:**")
                if notcoming.empty:
                    st.caption("Nog niemand.")
                else:
                    for _, ss in notcoming.iterrows():
                        st.write(f"- {ss.get('username') or 'lid'}")

            # Inschrijven — admin/user/member
            if role in {"admin","user","member"}:
                st.divider()
                st.markdown("**Mijn inschrijving**")

                prev = myrow.iloc[0] if not myrow.empty else {}
                prev_eating = bool(prev.get("eating")) if prev is not None else False
                prev_meal = prev.get("meal_choice") if prev is not None else None

                init_index = 0 if my_status in (None, "yes") else 1
                status_choice = st.radio("Status", ["Ik kom", "Ik kom niet"], horizontal=True,
                                         index=init_index, key=f"act_{rid}_status")

                eating = None; meal_choice = None
                meal_opts = row.get("meal_options") or []
                if status_choice == "Ik kom":
                    eating = st.checkbox("Ik eet mee", value=prev_eating, key=f"act_{rid}_eat")
                    if eating and meal_opts:
                        default_ix = 0
                        if prev_meal and prev_meal in meal_opts:
                            default_ix = (meal_opts.index(prev_meal) + 1)
                        mc = st.selectbox("Kies je maaltijd", ["— kies —"] + meal_opts,
                                          index=default_ix, key=f"act_{rid}_meal")
                        meal_choice = None if mc == "— kies —" else mc

                if st.button("Bewaar mijn keuze", key=f"act_{rid}_save", type="primary"):
                    try:
                        signup_upsert(
                            activiteit_id=row["id"],
                            username=user,
                            status=("yes" if status_choice == "Ik kom" else "no"),
                            eating=eating,
                            meal_choice=meal_choice
                        )
                        st.success("Inschrijving bijgewerkt."); st.rerun()
                    except Exception as e:
                        st.error(f"Opslaan mislukt: {e}")

            # Export / print
            st.markdown("---")
            st.markdown("**Afdruk / export inschrijvingen**")
            cols = ["username","status","eating","meal_choice","signup_ts"]
            cols = [c for c in cols if c in s.columns]
            print_df = s[cols].copy()
            print_df = print_df.rename(columns={
                "username":"Gebruiker","status":"Status","eating":"Eet mee",
                "meal_choice":"Maaltijd","signup_ts":"Ingeschreven op"
            })
            if not print_df.empty and "Ingeschreven op" in print_df.columns:
                print_df["Ingeschreven op"] = pd.to_datetime(print_df["Ingeschreven op"]).dt.strftime("%d/%m/%Y %H:%M")
            st.dataframe(print_df, use_container_width=True, hide_index=True)
            buf = io.BytesIO(); print_df.to_csv(buf, index=False)
            st.download_button("⬇️ Download CSV", data=buf.getvalue(),
                               file_name=f"inschrijvingen_{row['titel']}_{row['datum']}.csv",
                               mime="text/csv", key=f"act_{rid}_csv")

    # ADMIN: verwijderen
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

    # Weekmail preview/export (eerstvolgende 4)
    st.divider()
    st.subheader("Wekelijkse mail — eerstvolgende 4")
    mail_df = df.head(4).copy()
    rows = []
    for _, r in mail_df.iterrows():
        s = signups_get(r["id"])
        yes = int((s["status"]=="yes").sum()) if not s.empty else 0
        no  = int((s["status"]=="no").sum())  if not s.empty else 0
        rows.append({
            "Titel": r["titel"],
            "Datum": pd.to_datetime(r["datum"]).strftime("%d/%m/%Y"),
            "Tijd": r.get("tijd") or "",
            "Locatie": r.get("locatie") or "",
            "Teller": f"{yes} komen · {no} niet"
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

    tabs = st.tabs(["Kalender"])
    with tabs[0]:
        page_activiteiten()

if __name__ == "__main__":
    main()

