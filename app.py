# app.py
import os
import json
import httpx
import streamlit as st

# -----------------------------------------------------------------------------
# Config: Supabase creds via Streamlit secrets OR environment variables
# -----------------------------------------------------------------------------
def _get_supabase_env():
    url = None
    key = None
    try:
        url = st.secrets["supabase"]["url"]
        key = st.secrets["supabase"]["anon_key"]
    except Exception:
        url = os.environ.get("SUPABASE_URL", "").strip()
        key = os.environ.get("SUPABASE_ANON_KEY", "").strip()
    if not url or not key:
        st.error("❌ SUPABASE_URL of SUPABASE_ANON_KEY ontbreekt. Zet deze in .streamlit/secrets.toml of als env vars.")
    return url, key

SUPABASE_URL, SUPABASE_ANON_KEY = _get_supabase_env()


def _sb_headers():
    return {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
        "Prefer": "return=representation"
    }


# -----------------------------------------------------------------------------
# Data access: leden CRUD via Supabase REST
# -----------------------------------------------------------------------------
def leden_list():
    """Haal alle leden op, gesorteerd op achternaam/voornaam."""
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return False, "Supabase configuratie ontbreekt", []

    url = f"{SUPABASE_URL}/rest/v1/leden"
    params = {
        "select": "*",
        "order": "achternaam.asc,voornaam.asc"
    }
    try:
        with httpx.Client(timeout=30.0) as client:
            r = client.get(url, headers=_sb_headers(), params=params)
        if r.status_code == 200:
            return True, None, r.json()
        return False, f"HTTP {r.status_code}: {r.text}", []
    except Exception as e:
        return False, str(e), []


def leden_update(member_id: str, changes: dict):
    """PATCH een lid (enkel de fields in 'changes')."""
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return False, "Supabase configuratie ontbreekt"

    url = f"{SUPABASE_URL}/rest/v1/leden"
    params = {"id": f"eq.{member_id}"}
    try:
        with httpx.Client(timeout=30.0) as client:
            r = client.patch(url, headers=_sb_headers(), params=params, json=changes)
        if 200 <= r.status_code < 300:
            return True, r.json()
        return False, f"HTTP {r.status_code}: {r.text}"
    except Exception as e:
        return False, str(e)


def leden_delete(member_id: str):
    """DELETE een lid by id."""
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return False, "Supabase configuratie ontbreekt"

    url = f"{SUPABASE_URL}/rest/v1/leden"
    params = {"id": f"eq.{member_id}"}
    try:
        with httpx.Client(timeout=30.0) as client:
            r = client.delete(url, headers=_sb_headers(), params=params)
        if r.status_code in (200, 204):
            return True, None
        return False, f"HTTP {r.status_code}: {r.text}"
    except Exception as e:
        return False, str(e)


# -----------------------------------------------------------------------------
# UI helpers
# -----------------------------------------------------------------------------
def _field(col_label: str, value, key: str, kind: str = "text"):
    """Klein hulpje om consistente velden te maken."""
    if kind == "checkbox":
        return st.checkbox(col_label, bool(value), key=key)
    return st.text_input(col_label, value or "", key=key)


# -----------------------------------------------------------------------------
# Main UI: enkel ledenbeheer met admin-acties (bewerken/verwijderen)
# -----------------------------------------------------------------------------
def main():
    st.set_page_config(page_title="Ledenbeheer (Admin)", page_icon="🛠️", layout="wide")
    st.title("🛠️ Ledenbeheer (Admin)")
    st.caption("Alleen de **beheerder** ziet bewerken/verwijderen. Verder blijft alles ongemoeid.")

    # In jouw app komt dit uit de login/roles. Voor testdoeleinden laten we het togglebaar.
    # Als je al 'is_admin' in session_state zet in je bestaande app, dan mag je die gebruiken.
    if "is_admin" not in st.session_state:
        st.session_state.is_admin = True  # toggle default voor testen
    with st.sidebar:
        st.session_state.is_admin = st.checkbox("Admin-modus", value=st.session_state.is_admin, help="Simuleer beheerder")

    ok, err, leden = leden_list()
    if not ok:
        st.error(f"Kon leden niet laden: {err}")
        return

    # Filtertje
    q = st.text_input("Zoek op naam of e-mail", "")
    if q:
        q_low = q.lower().strip()
        leden = [l for l in leden if
                 (str(l.get("voornaam","")).lower().find(q_low) >= 0) or
                 (str(l.get("achternaam","")).lower().find(q_low) >= 0) or
                 (str(l.get("email","")).lower().find(q_low) >= 0) or
                 (str(l.get("username","")).lower().find(q_low) >= 0)]

    st.write(f"**{len(leden)}** leden gevonden.")

    # Lijst
    for lid in leden:
        lid_id = lid.get("id")
        display_name = f"{lid.get('voornaam','')} {lid.get('achternaam','')}".strip() or lid.get("username","(zonder naam)")
        base_info = f"📧 {lid.get('email','') or '—'}  ·  👤 {lid.get('username','')}  ·  🪪 {lid.get('login','') or '—'}  ·  🟢 Actief: {bool(lid.get('actief', True))}"
        st.markdown(f"### {display_name}")
        st.caption(base_info)

        if st.session_state.is_admin:
            with st.expander("⚙️ Beheer acties", expanded=False):
                c1, c2, c3 = st.columns([1,1,1])

                with c1:
                    v_voornaam   = _field("Voornaam",   lid.get("voornaam",""),   key=f"vn_{lid_id}")
                    v_achternaam = _field("Achternaam", lid.get("achternaam",""), key=f"an_{lid_id}")
                    v_email      = _field("E-mail",     lid.get("email",""),      key=f"em_{lid_id}")

                with c2:
                    v_login      = _field("Login",      lid.get("login",""),      key=f"lg_{lid_id}")
                    v_username   = _field("Username",   lid.get("username",""),   key=f"un_{lid_id}")
                    v_duikbrevet = _field("Duikbrevet", lid.get("duikbrevet",""), key=f"db_{lid_id}")

                with c3:
                    v_actief     = _field("Actief",     bool(lid.get("actief", True)), key=f"ac_{lid_id}", kind="checkbox")

                b1, b2 = st.columns([1,1])
                with b1:
                    if st.button("💾 Opslaan", key=f"save_{lid_id}"):
                        changes = {}
                        if v_voornaam.strip()   != (lid.get("voornaam") or ""):   changes["voornaam"]   = v_voornaam.strip()
                        if v_achternaam.strip() != (lid.get("achternaam") or ""): changes["achternaam"] = v_achternaam.strip()
                        if v_email.strip()      != (lid.get("email") or ""):      changes["email"]      = v_email.strip()
                        if v_login.strip()      != (lid.get("login") or ""):      changes["login"]      = v_login.strip()
                        if v_username.strip()   != (lid.get("username") or ""):   changes["username"]   = v_username.strip()
                        # Duikbrevet leeg -> None zodat CHECK niet faalt op '' (lege string)
                        db_new = v_duikbrevet.strip()
                        db_old = (lid.get("duikbrevet") or "").strip()
                        if db_new != db_old:
                            changes["duikbrevet"] = (db_new or None)
                        if bool(v_actief) != bool(lid.get("actief", True)):
                            changes["actief"] = bool(v_actief)

                        if not changes:
                            st.info("Niets gewijzigd.")
                        else:
                            ok_u, resp = leden_update(lid_id, changes)
                            if ok_u:
                                st.success("Lid bijgewerkt.")
                                st.experimental_rerun()
                            else:
                                st.error(f"Bijwerken mislukt: {resp}")

                with b2:
                    confirm = st.checkbox("Bevestig verwijderen", key=f"cfdel_{lid_id}")
                    if st.button("🗑️ Verwijder", key=f"del_{lid_id}"):
                        if not confirm:
                            st.warning("Vink eerst ‘Bevestig verwijderen’ aan.")
                        else:
                            ok_d, err = leden_delete(lid_id)
                            if ok_d:
                                st.success("Lid verwijderd.")
                                st.experimental_rerun()
                            else:
                                st.error(f"Verwijderen mislukt: {err}")

        st.divider()


if __name__ == "__main__":
    main()
