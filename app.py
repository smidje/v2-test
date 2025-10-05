# app.py — ANWW Duikapp • Build v2025-10-06
# Volledige versie met: login, activiteiten, duiken, afrekening, beheer gebruikers
# Auteur: ChatGPT 2025, opgeschoond en herwerkt
# Gebruik: plaats in hoofdmap van Streamlit-project en start met `streamlit run app.py`

# === IMPORTS ===
import streamlit as st
import pandas as pd
import datetime
import io
import hashlib
from supabase import create_client, Client
from postgrest.exceptions import APIError

# === BASIS CONFIGURATIE ===
st.set_page_config(page_title="ANWW Duikapp", layout="wide")
APP_BUILD = "v2025-10-06-full"

# === KLEUREN EN THEMA ===
def inject_css():
    st.markdown("""
    <style>
      :root{
        --background:#8DAEBA;
        --panel:#A38B16;
        --text:#11064D;
        --primary:#728DCC;
        --border:#2a355a;
      }
      .stApp, [data-testid="stAppViewContainer"], .main, div.block-container {
        background: var(--background) !important;
        color: var(--text) !important;
      }
      .stButton > button, .stDownloadButton > button {
        background-color: var(--primary) !important;
        color:#fff !important;
        border:2px solid var(--border) !important;
        border-radius:10px !important;
        padding:.45em 1.1em !important;
        font-weight:600 !important;
      }
      .stButton > button:hover {filter:brightness(1.08) !important; transform:translateY(-1px) !important;}
      .act-card {
        background:#ffffffb5; border:1px solid var(--border);
        border-radius:10px; padding:10px 14px; margin:8px 0 12px;
      }
      .act-line {display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap;}
      .act-tot {font-size:.9em; opacity:.9;}
    </style>
    """, unsafe_allow_html=True)

inject_css()

# === SUPABASE CLIENT ===
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
        st.error(f"API-fout bij {what}. Controleer tabel/policy/RLS ({e.code}).")
        raise
    except Exception as e:
        st.error(f"Fout bij {what}: {e}")
        raise

# === AUTHENTICATIE FUNCTIES ===
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def auth_lookup_user(login_id: str):
    r1 = run_db(lambda c: c.table("users")
                .select("username,password_hash,role").eq("username", login_id)
                .maybe_single().execute(), what="users select (username)")
    if r1.data: return r1.data
    try:
        r2 = run_db(lambda c: c.table("users")
                    .select("username,password_hash,role,email").eq("email", login_id)
                    .maybe_single().execute(), what="users select (email)")
        if r2.data:
            return {k: r2.data.get(k) for k in ["username","password_hash","role"]}
    except APIError:
        pass
    return None

def auth_check(login_id: str, password: str):
    rec = auth_lookup_user(login_id)
    if not rec: return None
    ph = (rec or {}).get("password_hash") or ""
    ok = (ph == sha256_hex(password)) or (ph == password)
    if not ok: return None
    return {"username": rec.get("username"), "role": (rec.get("role") or "viewer")}

def current_username(): return st.session_state.get("username")
def current_role(): return st.session_state.get("role","viewer")
def require_role(*roles):
    r = current_role()
    if r not in roles:
        st.warning("Je hebt geen toegang tot deze pagina.")
        st.stop()

# === LOGIN PAGINA ===
def login_page():
    st.title("Aanmelden")
    with st.form("login_form"):
        u = st.text_input("Gebruikersnaam of e-mail")
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

# === HULPFUNCTIES VOOR DATABASE ===
def plaatsen_list() -> list[str]:
    res = run_db(lambda c: c.table("duikplaatsen").select("name").order("name").execute(),
                 what="duikplaatsen select")
    return [r["name"] for r in (res.data or [])]

def plaats_add(name: str):
    run_db(lambda c: c.table("duikplaatsen").insert({"name": name}).execute(),
           what="duikplaats insert")

# === ACTIVITEITEN FUNCTIES ===
def activiteit_add(titel, omschr, datum, tijd, locatie, meal_opts, created_by, enable_counts=False):
    payload = {
        "titel": titel.strip(),
        "omschrijving": (omschr or "").strip() or None,
        "datum": datum.isoformat(),
        "tijd": tijd.strftime("%H:%M") if tijd else None,
        "locatie": (locatie or "").strip() or None,
        "meal_options": meal_opts or None,
        "created_by": created_by or None,
        "enable_counts": bool(enable_counts),
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

# === ACTIVITEITEN PAGINA ===
def page_activiteiten():
    st.header("Kalender & Inschrijvingen")

    # ADMIN: toevoegen
    if current_role() == "admin":
        with st.expander("➕ Nieuwe activiteit"):
            c1, c2 = st.columns([2,1])
            with c1:
                titel = st.text_input("Titel*")
                omschr = st.text_area("Omschrijving")
            with c2:
                datum = st.date_input("Datum*", value=datetime.date.today())
                tijd = st.time_input("Tijd (optioneel)", value=datetime.time(9,0))
                pl = plaatsen_list()
                locatie = st.selectbox("Locatie", ["— kies —"] + pl, index=0, key="act_loc_select")
                new_loc = st.text_input("Nieuwe locatie (indien niet in lijst)", key="act_new_loc")
                if st.button("➕ Locatie toevoegen", key="act_add_loc_btn"):
                    if new_loc and new_loc not in pl:
                        plaats_add(new_loc)
                        st.success("Locatie toegevoegd."); st.rerun()
                    else:
                        st.warning("Leeg of al bestaand.")

            st.caption("Maaltijdopties (max. 3, optioneel)")
            m1, m2, m3 = st.columns(3)
            with m1: mo1 = st.text_input("Optie 1", key="meal1")
            with m2: mo2 = st.text_input("Optie 2", key="meal2")
            with m3: mo3 = st.text_input("Optie 3", key="meal3")
            enable_counts = st.checkbox(
                "Extra inschrijfvelden: aantal volwassenen/kinderen + per persoon 'eet wel/niet'",
                value=False
            )

            if st.button("Activiteit toevoegen", type="primary", key="act_add_btn"):
                if not titel or not datum:
                    st.warning("Titel en datum zijn verplicht.")
                else:
                    meal_opts = [x.strip() for x in [mo1,mo2,mo3] if x and x.strip()]
                    activiteit_add(
                        titel, omschr, datum, tijd,
                        None if not locatie or locatie == "— kies —" else locatie.strip(),
                        meal_opts or None,
                        current_username(),
                        enable_counts=enable_counts
                    )
                    st.success("Activiteit aangemaakt."); st.rerun()

    # overzicht
    df = activiteiten_df(upcoming=True)
    if df.empty:
        st.info("Geen (toekomstige) activiteiten.")
        return
    df = df.sort_values(["datum","tijd"], na_position="last").reset_index(drop=True)

    for i, row in df.iterrows():
        rid = str(row.get("id") or f"idx{i}")
        datum_str = pd.to_datetime(row["datum"]).strftime("%d/%m/%Y")
        tijd_str = f" · {row['tijd']}" if row.get("tijd") else ""
        loc_str = f" · 📍 {row['locatie']}" if row.get("locatie") else ""
        st.markdown(f"<div class='act-card'><div class='act-line'><div><strong>{row['titel']}</strong> — {datum_str}{tijd_str}{loc_str}</div></div></div>", unsafe_allow_html=True)

    # ADMIN: verwijderen
    if current_role() == "admin":
        st.divider(); st.subheader("Activiteiten verwijderen")
        options, id_map = [], {}
        for _, r in df.iterrows():
            label = f"{pd.to_datetime(r['datum']).strftime('%d/%m/%Y')} · {r['titel']}" + (f" · 📍{r['locatie']}" if r.get("locatie") else "")
            options.append(label); id_map[label] = r["id"]
        sel = st.multiselect("Selecteer activiteiten", options, key="del_act_sel_admin")
        if st.button("Verwijderen", type="primary", disabled=not sel, key="del_act_btn_admin"):
            activiteiten_delete([id_map[x] for x in sel if x in id_map])
            st.success(f"Verwijderd: {len(sel)}"); st.rerun()

# === GEBRUIKERSBEHEER (ADMIN) ===
def page_users_admin():
    require_role("admin")
    st.header("Beheer gebruikers")

    st.subheader("Nieuwe gebruiker")
    with st.form("user_add_form", clear_on_submit=True):
        c1, c2, c3, c4 = st.columns([2,2,2,1])
        with c1: username = st.text_input("Gebruikersnaam*", key="ua_u")
        with c2: email = st.text_input("E-mail (optioneel)", key="ua_e")
        with c3: pw = st.text_input("Wachtwoord*", type="password", key="ua_p")
        with c4: role = st.selectbox("Rol", ["viewer","member","user","admin"], index=0, key="ua_r")
        ok = st.form_submit_button("Toevoegen", type="primary")
        if ok:
            if not username or not pw:
                st.warning("Gebruikersnaam en wachtwoord verplicht.")
            else:
                payload = {"username": username.strip(), "password_hash": sha256_hex(pw.strip()), "role": role}
                if email.strip(): payload["email"] = email.strip()
                run_db(lambda c: c.table("users").insert(payload).execute(), what="user insert")
                st.success("Gebruiker aangemaakt.")

    st.subheader("Gebruikerslijst")
    res = run_db(lambda c: c.table("users").select("username,email,role").order("username").execute(),
                 what="users list")
    df = pd.DataFrame(res.data or [])
    if df.empty: st.info("Nog geen gebruikers.")
    else: st.dataframe(df, use_container_width=True, hide_index=True)
# === DUIKEN ===
def duiken_list() -> pd.DataFrame:
    res = run_db(lambda c: c.table("duiken").select("*").order("datum", desc=True).execute(),
                 what="duiken select")
    return pd.DataFrame(res.data or [])

def duik_add(datum, plaats, buddy, diepte, tijd, duiker):
    payload = {
        "datum": datum.isoformat(),
        "plaats": plaats,
        "buddy": buddy,
        "diepte": diepte,
        "tijd": tijd,
        "duiker": duiker
    }
    run_db(lambda c: c.table("duiken").insert(payload).execute(), what="duik insert")

def duik_delete(ids: list[str]):
    if not ids: return
    run_db(lambda c: c.table("duiken").delete().in_("id", ids).execute(),
           what="duiken delete")

def page_duiken():
    st.header("Duikenoverzicht")

    # Toevoegen (users of admins)
    if current_role() in {"admin", "user"}:
        with st.expander("➕ Nieuwe duik toevoegen"):
            c1, c2, c3, c4 = st.columns([1.5,1.5,1,1])
            with c1:
                datum = st.date_input("Datum", value=datetime.date.today(), key="d_datum")
                plaats = st.selectbox("Duikplaats", ["— kies —"] + plaatsen_list(), key="d_plaats")
            with c2:
                buddy = st.text_input("Buddy", key="d_buddy")
                diepte = st.number_input("Diepte (m)", 0.0, 100.0, 0.0, 0.5, key="d_diepte")
            with c3:
                tijd = st.number_input("Duur (minuten)", 0, 400, 0, 1, key="d_tijd")
                duiker = st.text_input("Duiker", value=current_username(), key="d_duiker")
            if st.button("Duik toevoegen", type="primary", key="d_add"):
                if not plaats or plaats == "— kies —":
                    st.warning("Duikplaats verplicht.")
                else:
                    duik_add(datum, plaats, buddy, diepte, tijd, duiker)
                    st.success("Duik toegevoegd.")
                    st.rerun()

    # Lijst duiken
    df = duiken_list()
    if df.empty:
        st.info("Nog geen duiken geregistreerd.")
        return
    df = df.sort_values("datum", ascending=False)
    st.dataframe(df, use_container_width=True, hide_index=True)

    # Verwijderen (alleen admin)
    if current_role() == "admin":
        st.divider()
        st.subheader("Duiken verwijderen")
        ids = [str(i) for i in df["id"].tolist()] if "id" in df.columns else []
        labels = [f"{r['datum']} · {r['plaats']} ({r['duiker']})" for _, r in df.iterrows()]
        sel = st.multiselect("Selecteer te verwijderen duiken", labels)
        id_map = {lbl: df.iloc[i]["id"] for i, lbl in enumerate(labels) if "id" in df.columns}
        if st.button("Verwijderen", type="primary", disabled=not sel, key="d_del"):
            duik_delete([id_map[s] for s in sel])
            st.success("Duiken verwijderd.")
            st.rerun()

# === AFREKENING ===
def afrekening_list() -> pd.DataFrame:
    res = run_db(lambda c: c.table("afrekening").select("*").execute(),
                 what="afrekening select")
    return pd.DataFrame(res.data or [])

def afrekening_add(datum, duiker, bedrag, omschrijving):
    payload = {"datum": datum.isoformat(), "duiker": duiker,
               "bedrag": bedrag, "omschrijving": omschrijving}
    run_db(lambda c: c.table("afrekening").insert(payload).execute(), what="afrekening insert")

def afrekening_delete(ids: list[str]):
    if not ids: return
    run_db(lambda c: c.table("afrekening").delete().in_("id", ids).execute(),
           what="afrekening delete")

def page_afrekening():
    st.header("Afrekening")

    if current_role() in {"admin", "user"}:
        with st.expander("➕ Nieuwe afrekening toevoegen"):
            c1, c2, c3, c4 = st.columns([1,1,1,2])
            with c1:
                datum = st.date_input("Datum", value=datetime.date.today(), key="afr_datum")
            with c2:
                duiker = st.text_input("Duiker", key="afr_duiker")
            with c3:
                bedrag = st.number_input("Bedrag (€)", 0.0, 9999.99, 0.0, 0.5, key="afr_bedrag")
            with c4:
                omschr = st.text_input("Omschrijving", key="afr_oms")
            if st.button("Toevoegen", type="primary", key="afr_add"):
                if not duiker or bedrag == 0:
                    st.warning("Duiker en bedrag verplicht.")
                else:
                    afrekening_add(datum, duiker, bedrag, omschr)
                    st.success("Afrekening toegevoegd.")
                    st.rerun()

    df = afrekening_list()
    if df.empty:
        st.info("Nog geen afrekeningen geregistreerd.")
        return
    st.dataframe(df, use_container_width=True, hide_index=True)

    if current_role() == "admin":
        st.divider(); st.subheader("Afrekeningen verwijderen")
        ids = [str(i) for i in df["id"].tolist()] if "id" in df.columns else []
        labels = [f"{r['datum']} · {r['duiker']} · €{r['bedrag']}" for _, r in df.iterrows()]
        sel = st.multiselect("Selecteer te verwijderen afrekeningen", labels)
        id_map = {lbl: df.iloc[i]["id"] for i, lbl in enumerate(labels) if "id" in df.columns}
        if st.button("Verwijderen", type="primary", disabled=not sel, key="afr_del"):
            afrekening_delete([id_map[s] for s in sel])
            st.success("Afrekeningen verwijderd.")
            st.rerun()

# === HOOFDSTRUCTUUR / MAIN ===
def main():
    st.sidebar.title("ANWW Duikapp")
    if "username" not in st.session_state:
        login_page(); return

    st.sidebar.markdown(f"**Ingelogd als:** {current_username()} ({current_role()})")
    if st.sidebar.button("Uitloggen"):
        st.session_state.clear(); st.rerun()

    role = current_role()
    if role == "admin":
        tabs = st.tabs(["Kalender", "Duiken", "Afrekening", "Beheer gebruikers"])
        with tabs[0]: page_activiteiten()
        with tabs[1]: page_duiken()
        with tabs[2]: page_afrekening()
        with tabs[3]: page_users_admin()
    elif role in {"user"}:
        tabs = st.tabs(["Kalender", "Duiken", "Afrekening"])
        with tabs[0]: page_activiteiten()
        with tabs[1]: page_duiken()
        with tabs[2]: page_afrekening()
    elif role in {"member"}:
        tabs = st.tabs(["Kalender"])
        with tabs[0]: page_activiteiten()
    else:
        tabs = st.tabs(["Afrekening (alleen lezen)"])
        with tabs[0]: page_afrekening()

if __name__ == "__main__":
    main()
