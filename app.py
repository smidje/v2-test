# app.py — ANWW Duikapp (login via username + wachtwoord) • Build v2025-10-03-LOCAL-USER-LOGIN
# Schoon bestand zonder restjes/snippet-IDs.
# Functies: Activiteitenkalender (met inschrijven + tot 3 maaltijdkeuzes),
# Afrekening (alleen duikers tellen mee), Duiken invoeren/overzicht, Beheer (leden),
# Wekelijkse mail preview/export (eerstvolgende 4 activiteiten).

import streamlit as st
import pandas as pd
import datetime
from datetime import datetime as dt
import io
import os
import time
import math
import hmac, hashlib, secrets, base64
from typing import Optional
from supabase import create_client, Client
from postgrest.exceptions import APIError
import httpx

# ──────────────────────────────────────────────────────────────────────────────
# Basis UI & config
# ──────────────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="ANWW Duikapp", layout="wide")
APP_BUILD = "v2025-10-03-LOCAL-USER-LOGIN"

def inject_css():
    st.markdown("""
    <style>
      /* ====== Kleuren uit jouw palet ====== */
      :root {
        --background: #8DAEBA;
        --secondary: #A38B16;
        --text: #11064D;
        --primary: #728DCC;
        --border: #2a355a;
        --success: #3CA133;
        --warning: #f59e0b;
        --error: #ef4444;
      }

      /* ====== Achtergrond en tekst ====== */
      .stApp, [data-testid="stAppViewContainer"], section.main, div.block-container {
        background-color: var(--background) !important;
        color: var(--text) !important;
      }

      /* ====== Sidebar ====== */
      section[data-testid="stSidebar"], [data-testid="stSidebarContent"] {
        background-color: var(--secondary) !important;
      }

      /* ====== Tabs / Expanders ====== */
      .stTabs [data-baseweb="tab"] {
        background: var(--secondary) !important;
        color: #fff !important;
        border-radius: 5px 5px 0 0;
        font-weight: 600;
      }
      .stTabs [aria-selected="true"] {
        background: var(--primary) !important;
        color: white !important;
      }

      .stExpander {
        border: 1px solid var(--border) !important;
        background: #ffffff80 !important;
      }

      /* ====== Knoppen ====== */
      .stButton > button, .stDownloadButton > button {
        background-color: var(--primary) !important;
        color: #fff !important;
        border: 2px solid var(--border) !important;
        border-radius: 10px !important;
        padding: 0.4em 1em !important;
        font-weight: 600 !important;
        transition: all 0.15s ease-in-out !important;
      }
      .stButton > button:hover, .stDownloadButton > button:hover {
        filter: brightness(1.1) !important;
        transform: translateY(-1px);
      }

      /* Varianten voor HTML-knoppen */
      .stButton.success > button { background: var(--success) !important; border-color: var(--success) !important; }
      .stButton.warning > button { background: var(--warning) !important; color:#000 !important; border-color: var(--warning) !important; }
      .stButton.error   > button { background: var(--error)   !important; border-color: var(--error)   !important; }

      /* ====== Tabellen ====== */
      [data-testid="stDataFrame"] thead tr th {
        background: #ffffff88 !important;
        color: var(--text) !important;
      }

      /* ====== Kleine accenten ====== */
      hr, .stDivider {
        border-top: 2px solid var(--border) !important;
      }

      /* ====== Titels ====== */
      h1, h2, h3, h4, h5 {
        color: var(--text) !important;
      }
    </style>
    """, unsafe_allow_html=True)
inject_css()




def is_readonly() -> bool:
    return bool(st.secrets.get("app", {}).get("force_readonly", False))

# ──────────────────────────────────────────────────────────────────────────────
# Supabase client + DB helper
# ──────────────────────────────────────────────────────────────────────────────
@st.cache_resource
def get_client() -> Client:
    supa = st.secrets.get("supabase", {})
    url = supa.get("url") or os.getenv("SUPABASE_URL")
    key = supa.get("anon_key") or os.getenv("SUPABASE_ANON_KEY")
    if not url or not key:
        st.error("Supabase credentials ontbreken. Zet [supabase].url en anon_key in secrets.toml.")
        st.stop()
    return create_client(url, key)

sb: Client = get_client()

def run_db(fn, *, what="db call", tries=2, backoff=0.4):
    for i in range(tries):
        try:
            return fn(sb)
        except (httpx.ConnectError, httpx.ReadTimeout) as e:
            if i+1 < tries:
                time.sleep(backoff * (i+1))
                continue
            st.error(f"Netwerkfout bij {what}: {e}"); st.stop()
        except APIError as e:
            st.error(f"API-fout bij {what}. Controleer tabellen/RLS/policies (anon).")
            st.caption(str(e)); st.stop()
        except Exception as e:
            if i+1 < tries:
                time.sleep(backoff * (i+1))
                continue
            st.error(f"Onverwachte fout bij {what}: {e}"); st.stop()

# ──────────────────────────────────────────────────────────────────────────────
# Lokale AUTH in auth_local: login via USERNAME + wachtwoordhash + rol
# ──────────────────────────────────────────────────────────────────────────────
# Hashformaat: "pbkdf2$<iters>$<salt_hex>$<hash_hex>"
def _hash_password(password: str, iterations: int = 240000) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2${iterations}${salt.hex()}${dk.hex()}"

def _verify_password(password: str, hashed: str) -> bool:
    """
    Supports multiple legacy formats so bestaande accounts kunnen blijven inloggen:
    - "pbkdf2$<iters>$<salt_hex>$<hash_hex>"  (huidig formaat)
    - "pbkdf2:sha256:<iters>$<salt>$<hash_b64>"  (Flask/Werkzeug-achtig)
    - "$2a$..."/"$2b$..."/"$2y$..."  (bcrypt)
    """
    try:
        if not hashed:
            return False
        # 1) Huidig formaat: pbkdf2$iters$salt_hex$hash_hex
        if hashed.startswith("pbkdf2$"):
            try:
                algo, iters, salt_hex, hash_hex = hashed.split("$", 3)
                iters = int(iters)
                salt = bytes.fromhex(salt_hex)
                ref = bytes.fromhex(hash_hex)
                test = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
                return hmac.compare_digest(ref, test)
            except Exception:
                return False

        # 2) Flask/Werkzeug-achtig: pbkdf2:sha256:iters$salt$hash_b64
        if hashed.startswith("pbkdf2:sha256"):
            try:
                left, salt, hash_b64 = hashed.split("$", 2)
                parts = left.split(":")
                iters = None
                for p in reversed(parts):
                    if p.isdigit():
                        iters = int(p)
                        break
                if iters is None:
                    iters = 260000  # redelijke default
                salt_bytes = salt.encode("utf-8")
                test = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iters)
                # decode stored b64 (len must be multiple of 4)
                pad = "=" * (-len(hash_b64) % 4)
                ref = base64.b64decode(hash_b64 + pad)
                return hmac.compare_digest(ref, test)
            except Exception:
                return False

        # 3) bcrypt: $2a$ / $2b$ / $2y$
        if hashed.startswith("$2a$") or hashed.startswith("$2b$") or hashed.startswith("$2y$"):
            try:
                import bcrypt  # lazy import; staat in requirements.txt
                return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
            except Exception:
                return False

        # Onbekend formaat
        return False
    except Exception:
        return False

def auth_get_user_by_username(login: str) -> Optional[dict]:
    """Login primair op username; als dat niets oplevert én login ziet eruit als e-mail, proberen we email."""
    login = (login or "").strip()
    if not login:
        return None
    # 1) op username
    res = run_db(lambda c: c.table("auth_local").select("*").eq("username", login).limit(1).execute(),
                 what="auth_local select by username")
    rows = res.data or []
    if rows:
        return rows[0]
    # 2) fallback: op e-mail (als login e-mail lijkt)
    if "@" in login:
        res2 = run_db(lambda c: c.table("auth_local").select("*").eq("email", login.lower()).limit(1).execute(),
                      what="auth_local select by email")
        rows2 = res2.data or []
        if rows2:
            return rows2[0]
    return None

def auth_count_admins() -> int:
    res = run_db(lambda c: c.table("auth_local").select("id", count="exact").eq("role","admin").execute(),
                 what="auth_local count admin")
    return res.count or 0

def auth_create_user(username: str, password: str, role: str, email: str | None = None):
    if is_readonly():
        raise Exception("Read-only modus")
    role = (role or "viewer").strip().lower()
    if role not in {"admin","user","member","viewer"}:
        role = "viewer"
    payload = {
        "username": (username or "").strip(),
        "email": (email or "").strip().lower() or None,
        "password_hash": _hash_password(password),
        "role": role,
    }
    run_db(lambda c: c.table("auth_local").insert(payload).execute(), what="auth_local insert")

def auth_update_password_by_username(username: str, new_pw: str):
    if is_readonly():
        raise Exception("Read-only modus")
    run_db(lambda c: c.table("auth_local").update({"password_hash": _hash_password(new_pw)}).eq("username", username).execute(),
           what="auth_local update password")

def current_user():
    return st.session_state.get("auth_user") or {}

def current_role() -> str:
    u = current_user()
    r = (u.get("role") or "viewer").lower()
    return r if r in {"admin","user","member","viewer"} else "viewer"

def current_username() -> str:
    return (current_user().get("username") or "").strip()

def current_email() -> str:
    return (current_user().get("email") or "").strip().lower()

# ──────────────────────────────────────────────────────────────────────────────
# Tabellen & helpers
# ──────────────────────────────────────────────────────────────────────────────
BREVET_CHOICES = ['k1ster','1ster','2ster','3ster','4ster','ass-inst','1*inst','2*inst','3*inst']
ROLE_CHOICES = ['admin','user','member','viewer']

def leden_upsert(payload: dict):
    if is_readonly():
        raise Exception("Read-only modus")
    run_db(lambda c: c.table("leden").upsert(payload, on_conflict="email").execute(),
           what="leden upsert")

def leden_list_df() -> pd.DataFrame:
    res = run_db(lambda c: c.table("leden").select("*").order("achternaam").order("voornaam").execute(),
                 what="leden select")
    return pd.DataFrame(res.data or [])

def leden_get_by_email(email: str) -> Optional[dict]:
    email = (email or "").lower().strip()
    if not email:
        return None
    res = run_db(lambda c: c.table("leden").select("*").eq("email", email).limit(1).execute(),
                 what="leden by email")
    rows = res.data or []
    return rows[0] if rows else None

def leden_get_by_username(username: str) -> Optional[dict]:
    if not username:
        return None
    res = run_db(lambda c: c.table("leden").select("*").eq("username", username).limit(1).execute(),
                 what="leden by username")
    rows = res.data or []
    return rows[0] if rows else None

def duikers_labels() -> list[str]:
    res = run_db(lambda c: c.table("duikers").select("voornaam, achternaam, naam").execute(),
                 what="duikers select")
    rows = res.data or []
    out = []
    for r in rows:
        vn, an = (r.get("voornaam") or "").strip(), (r.get("achternaam") or "").strip()
        out.append(f"{an}, {vn}".strip(", ") if (vn or an) else (r.get("naam") or "").strip())
    def key(x):
        if "," in x:
            an, vn = [p.strip() for p in x.split(",", 1)]
            return (an.lower(), vn.lower())
        parts = x.split()
        return (parts[-1].lower() if parts else "", " ".join(parts[:-1]).lower())
    return sorted([o for o in out if o], key=key)

def plaatsen_list() -> list[str]:
    res = run_db(lambda c: c.table("duikplaatsen").select("plaats").order("plaats").execute(),
                 what="duikplaatsen select")
    return [r["plaats"] for r in (res.data or [])]

def plaats_add(plaats: str):
    if is_readonly():
        raise Exception("Read-only modus")
    run_db(lambda c: c.table("duikplaatsen").insert({"plaats": plaats}).execute(),
           what="duikplaatsen insert")

def duiken_insert(rows: list[dict]):
    if is_readonly():
        raise Exception("Read-only modus")
    if rows:
        run_db(lambda c: c.table("duiken").insert(rows).execute(), what="duiken insert")

def duiken_fetch_df() -> pd.DataFrame:
    res = run_db(lambda c: c.table("duiken").select("*").order("datum", desc=True).order("plaats").order("duiker").execute(),
                 what="duiken select")
    return pd.DataFrame(res.data or [])

def duiken_delete_by_ids(ids: list):
    if is_readonly():
        raise Exception("Read-only modus")
    if ids:
        run_db(lambda c: c.table("duiken").delete().in_("id", ids).execute(), what="duiken delete")

def afrekening_insert(row: dict):
    if is_readonly():
        raise Exception("Read-only modus")
    run_db(lambda c: c.table("afrekeningen").insert(row).execute(), what="afrekeningen insert")

def activiteit_add(titel, omschr, datum, tijd, locatie, meal_opts, created_by):
    if is_readonly():
        raise Exception("Read-only modus")
    payload = {
        "titel": titel.strip(),
        "omschrijving": (omschr or "").strip(),
        "datum": datum.isoformat(),
        "tijd": tijd.isoformat() if tijd else None,
        "locatie": (locatie or "").strip() or None,
        "meal_options": meal_opts or None,
        "created_by": created_by or None
    }
    run_db(lambda c: c.table("activiteiten").insert(payload).execute(), what="activiteiten insert")

def activiteiten_list_df(upcoming=True) -> pd.DataFrame:
    def _go(c):
        q = c.table("activiteiten").select("*")
        if upcoming:
            q = q.gte("datum", datetime.date.today().isoformat())
        return q.order("datum").order("tijd").execute()
    res = run_db(_go, what="activiteiten select")
    return pd.DataFrame(res.data or [])

def signups_get(activiteit_id: str) -> pd.DataFrame:
    res = run_db(lambda c: c.table("activity_signups").select("*").eq("activiteit_id", activiteit_id).order("signup_ts").execute(),
                 what="signups select")
    df = pd.DataFrame(res.data or [])
    for col in ["id","activiteit_id","username","lid_id","status","eating","meal_choice","signup_ts"]:
        if col not in df.columns:
            df[col] = None
    try:
        df["signup_ts"] = pd.to_datetime(df["signup_ts"], errors="coerce")
    except Exception:
        pass
    return df

def signup_upsert(activiteit_id: str, username: str | None, lid_id: str | None,
                  status: str, eating: bool | None, meal_choice: str | None):
    if is_readonly():
        raise Exception("Read-only modus")
    assert status in ("yes","no")
    def _lookup(c):
        q = c.table("activity_signups").select("id").eq("activiteit_id", activiteit_id)
        if username: q = q.eq("username", username)
        if lid_id: q = q.eq("lid_id", lid_id)
        return q.limit(1).execute()
    found = run_db(_lookup, what="signups find")
    rows = found.data or []
    payload = {
        "activiteit_id": activiteit_id,
        "status": status,
        "eating": bool(eating) if eating is not None else None,
        "meal_choice": (meal_choice or "").strip() or None,
        "username": username or None,
        "lid_id": lid_id or None,
        "signup_ts": dt.utcnow().isoformat()
    }
    if rows:
        sid = rows[0]["id"]
        run_db(lambda c: c.table("activity_signups").update(payload).eq("id", sid).execute(), what="signups update")
    else:
        run_db(lambda c: c.table("activity_signups").insert(payload).execute(), what="signups insert")

# ──────────────────────────────────────────────────────────────────────────────
# UI helpers
# ──────────────────────────────────────────────────────────────────────────────
def appbar(tag: str):
    col1, col2, col3 = st.columns([5, 3, 2])
    with col1:
        st.markdown("**ANWW Duikapp**")
    with col2:
        st.markdown(f"<div class='badge'>{current_username() or '—'} · {current_role()} · Build {APP_BUILD}</div>",
                    unsafe_allow_html=True)
    with col3:
        if st.button("Uitloggen", key=f"logout_{tag}"):
            st.session_state.pop("auth_user", None)
            st.rerun()

def require_role(*allowed):
    if current_role() not in allowed:
        st.error("Onvoldoende rechten.")
        st.stop()

# ──────────────────────────────────────────────────────────────────────────────
# Pagina's
# ──────────────────────────────────────────────────────────────────────────────
def page_setup_first_admin_username():
    st.title("Eerste admin aanmaken")
    st.info("Er bestaat nog geen admin. Maak eerst de eerste admin aan.")
    with st.form("first_admin"):
        username = st.text_input("Login (gebruikersnaam)", placeholder="vb. d.verbraeken")
        pw1 = st.text_input("Wachtwoord", type="password")
        pw2 = st.text_input("Herhaal wachtwoord", type="password")
        email = st.text_input("E-mail (optioneel)")
        submitted = st.form_submit_button("Maak admin", type="primary")
    if submitted:
        if not username or not pw1 or len(pw1) < 8 or pw1 != pw2:
            st.error("Controleer login en wachtwoord (min. 8 tekens en gelijk).")
            return
        try:
            auth_create_user(username=username, password=pw1, role="admin", email=email or None)
            # maak ook minimale ledenrij (email optioneel)
            payload = {
                "voornaam": "",
                "achternaam": "",
                "email": (email or "").strip().lower() or f"{username}@local",
                "username": username,
                "role": "admin",
                "opt_in_weekly": True,
                "actief": True
            }
            leden_upsert(payload)
            st.success("Admin aangemaakt. Je kan nu inloggen.")
            st.session_state["just_created_admin"] = True
        except Exception as e:
            st.error(f"Mislukt: {e}")

def page_login_username():
    st.title("Inloggen")
    if st.session_state.get("just_created_admin"):
        st.success("Admin aangemaakt. Log nu in.")
        st.session_state.pop("just_created_admin", None)

    with st.form("login_form"):
        login = st.text_input("Login (gebruikersnaam)")
        pw = st.text_input("Wachtwoord", type="password")
        submitted = st.form_submit_button("Login", type="primary")
    if not submitted:
        return
    user = auth_get_user_by_username(login)
    if not user or not _verify_password(pw, user.get("password_hash") or ""):
        st.error("Onjuiste login.")
        return
    st.session_state["auth_user"] = {
        "id": user.get("id"),
        "username": user.get("username"),
        "email": user.get("email"),
        "role": user.get("role"),
    }
    st.success("Ingelogd.")
    st.rerun()

def page_profiel():
    appbar("profiel")
    st.header("Mijn profiel")
    u = current_user()
    st.write(f"**Login (username):** {u.get('username')}")
    st.write(f"**Rol:** {u.get('role')}")
    if u.get("email"):
        st.write(f"**E-mail:** {u.get('email')}")

    st.divider()
    st.subheader("Wekelijkse mail")
    row = leden_get_by_username(current_username())
    cur_opt = bool((row or {}).get("opt_in_weekly", True))
    new_opt = st.toggle("Ik wil de wekelijkse activiteitenmail ontvangen", value=cur_opt)
    if st.button("Bewaar voorkeur"):
        try:
            email = (row or {}).get("email") or f"{current_username()}@local"
            leden_upsert({ "email": email, "username": current_username(), "opt_in_weekly": bool(new_opt) })
            st.success("Opgeslagen.")
        except Exception as e:
            st.error(f"Mislukt: {e}")

    st.divider()
    st.subheader("Wachtwoord wijzigen")
    c1, c2 = st.columns(2)
    with c1:
        npw1 = st.text_input("Nieuw wachtwoord", type="password")
        npw2 = st.text_input("Herhaal nieuw wachtwoord", type="password")
    if st.button("Wijzig wachtwoord"):
        if not npw1 or len(npw1) < 8 or npw1 != npw2:
            st.warning("Min. 8 tekens en beide velden moeten gelijk zijn.")
        else:
            try:
                auth_update_password_by_username(current_username(), npw1)
                st.success("Wachtwoord gewijzigd.")
            except Exception as e:
                st.error(f"Mislukt: {e}")

def page_ledenbeheer():
    payload = {}
    require_role("admin")
    if is_readonly():
        st.warning("Read-only modus actief — wijzigen uitgeschakeld.")
    appbar("ledenbeheer")
    st.header("Ledenbeheer (admin)")

    df = leden_list_df()
    if not df.empty:
        cols = ["voornaam","achternaam","email","username","role","duikbrevet","opt_in_weekly","actief"]
        show = [c for c in cols if c in df.columns]
        st.dataframe(df[show].sort_values(["achternaam","voornaam"], na_position="last"), use_container_width=True, hide_index=True)
    else:
        st.info("Nog geen leden.")

    st.divider()
    st.subheader("Lid toevoegen / bijwerken")
    with st.form("leden_form"):
        c1, c2, c3 = st.columns(3)
        with c1:
            vn = st.text_input("Voornaam")
            an = st.text_input("Achternaam")
            email = st.text_input("E-mail (mag leeg, maar uniek vereist in leden)")
        with c2:
            username = st.text_input("Login (username)*")
            role = st.selectbox("Rol/functie", options=ROLE_CHOICES, index=2)  # default member
        with c3:
            brevet = st.selectbox("Duikbrevet", options=["(geen)"] + BREVET_CHOICES, index=0)
            optin = st.toggle("Wekelijkse mail", value=True)
            actief = st.toggle("Actief", value=True)
        pw1 = st.text_input("Initieel wachtwoord (alleen bij 1e keer toevoegen)", type="password")
        pw2 = st.text_input("Herhaal wachtwoord", type="password")
        submitted = st.form_submit_button("Bewaar lid", type="primary")

    if submitted:
        if not username:
            st.warning("Login (username) is verplicht."); return
        # leden.email is uniek en verplicht; maak lokaal e-mailadres als admin het leeg laat
        email_eff = (email or "").strip().lower() or f"{username.strip()}@local"
        payload = {
            "email": email_eff,
            "voornaam": (vn or "").strip(),
            "achternaam": (an or "").strip(),
            "username": username.strip(),
            "role": role,
            "duikbrevet": None if brevet == "(geen)" else brevet,
            "opt_in_weekly": bool(optin),
            "actief": bool(actief)
        }
        try:
            leden_upsert(payload)
            # auth_local
            u = auth_get_user_by_username(username)
            if not u:
                if not pw1 or len(pw1) < 8 or pw1 != pw2:
                    st.warning("Nieuwe login vereist wachtwoord (min. 8 tekens) en beide velden gelijk.")
                    return
                auth_create_user(username=username, password=pw1, role=role, email=(email or None))
            else:
                if not is_readonly():
                    run_db(lambda c: c.table("auth_local").update({
                        "role": role,
                        "email": (email or "").strip().lower() or None
                    }).eq("username", username).execute(), what="auth_local update")
            st.success("Lid + login bewaard.")
            st.rerun()
        except Exception as e:
            st.error(f"Bewaren mislukt: {e}")

    st.divider()
    st.subheader("Login resetten (nieuw wachtwoord zetten)")
    with st.form("reset_pw"):
        uname = st.text_input("Login (username) van lid")
        npw1 = st.text_input("Nieuw wachtwoord", type="password")
        npw2 = st.text_input("Herhaal nieuw wachtwoord", type="password")
        ok = st.form_submit_button("Zet nieuw wachtwoord")
    if ok:
        if not uname or not npw1 or len(npw1) < 8 or npw1 != npw2:
            st.warning("Controleer login en wachtwoord (min. 8 tekens, gelijk).")
        else:
            try:
                if not auth_get_user_by_username(uname):
                    st.warning("Er bestaat nog geen login voor deze username. Maak eerst het lid aan (met initieel wachtwoord).")
                else:
                    auth_update_password_by_username(uname, npw1)
                    st.success("Wachtwoord gereset.")
            except Exception as e:
                st.error(f"Reset mislukt: {e}")

def page_activiteiten():
    # Iedereen kan zien; inschrijven: admin/user/member
    appbar("activiteiten")
    st.header("Kalender & Inschrijvingen")

    # ──────────────────────────────────────────────────────────────────────────
    # ADMIN: activiteit toevoegen (incl. locatie uit duikplaatsen en 3 meal-opties)
    # ──────────────────────────────────────────────────────────────────────────
    if current_role() == "admin":
        with st.expander("➕ Nieuwe activiteit"):
            c1, c2 = st.columns([2, 1])
            with c1:
                titel = st.text_input("Titel*")
                omschr = st.text_area("Omschrijving")
            with c2:
                datum = st.date_input("Datum*", value=datetime.date.today())
                tijd = st.time_input("Tijd (optioneel)", value=None)

                # Locatie uit duikplaatsen + snel toevoegen
                pl = plaatsen_list()
                locatie = st.selectbox("Locatie", ["— kies —"] + pl, index=0, key="act_loc_select")
                new_loc = st.text_input("Nieuwe locatie (indien niet in lijst)", key="act_new_loc")
                if st.button("➕ Locatie toevoegen", key="act_add_loc_btn", disabled=is_readonly()):
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

            if st.button("Activiteit toevoegen", type="primary", key="act_add_btn", disabled=is_readonly()):
                if not titel or not datum:
                    st.warning("Titel en datum zijn verplicht.")
                else:
                    meal_opts = [x.strip() for x in [mo1, mo2, mo3] if x and x.strip()]
                    try:
                        activiteit_add(
                            titel=titel,
                            omschr=omschr,
                            datum=datum,
                            tijd=tijd,
                            locatie=None if not locatie or locatie == "— kies —" else locatie.strip(),
                            meal_opts=meal_opts or None,
                            created_by=current_username() or current_email()
                        )
                        st.success("Activiteit aangemaakt.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Mislukt: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Overzicht komende activiteiten
    # ──────────────────────────────────────────────────────────────────────────
    df = activiteiten_list_df(upcoming=True)
    if df.empty:
        st.info("Geen (toekomstige) activiteiten.")
        return

    # Identiteit voor inschrijven
    my_username = current_username()
    my_lid = leden_get_by_username(my_username)
    my_lid_id = (my_lid or {}).get("id")

    # Toon activiteiten (gesorteerd op datum/tijd)
    for _, row in df.sort_values(["datum", "tijd"], na_position="last").iterrows():
        s = signups_get(row["id"])

        # mijn huidige status
        myrow = None
        if my_username:
            tmp = s.loc[s["username"] == my_username]
            if not tmp.empty:
                myrow = tmp
        if (myrow is None or myrow.empty) and my_lid_id:
            tmp = s.loc[s["lid_id"] == my_lid_id]
            if not tmp.empty:
                myrow = tmp
        my_status = (myrow.iloc[0]["status"] if (myrow is not None and not myrow.empty) else None)
        badge = "🟢 ingeschreven" if my_status == "yes" else ("🔴 niet ingeschreven" if my_status == "no" else "⚪ nog niet gekozen")

        titel = f"{row['titel']} — {pd.to_datetime(row['datum']).strftime('%d/%m/%Y')}"
        if row.get("tijd"):
            titel += f" · {row['tijd']}"

        with st.expander(f"{titel}   ·   {badge}", expanded=False):
            if row.get("locatie"):
                st.caption(f"📍 {row['locatie']}")
            if row.get("omschrijving"):
                st.write(row["omschrijving"])

            # Lijsten op volgorde van inschrijving
            coming = s.loc[s["status"] == "yes"].sort_values("signup_ts")
            notcoming = s.loc[s["status"] == "no"].sort_values("signup_ts")

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
            if current_role() in {"admin", "user", "member"} and not is_readonly():
                st.divider()
                st.markdown("**Mijn inschrijving**")
                prev_eating, prev_meal = False, None
                if myrow is not None and not myrow.empty:
                    if pd.notna(myrow.iloc[0].get("eating")):
                        prev_eating = bool(myrow.iloc[0].get("eating"))
                    pm = myrow.iloc[0].get("meal_choice")
                    prev_meal = pm if isinstance(pm, str) and pm.strip() else None

                init_index = 0 if my_status in (None, "yes") else 1
                status = st.radio("Status", ["Ik kom", "Ik kom niet"], horizontal=True, index=init_index, key=f"st_{row['id']}")
                eating = None
                meal_choice = None
                meal_opts = row.get("meal_options") or []
                if status == "Ik kom":
                    eating = st.checkbox("Ik eet mee", value=prev_eating, key=f"eat_{row['id']}")
                    if eating and meal_opts:
                        default_ix = 0
                        if prev_meal and prev_meal in meal_opts:
                            default_ix = meal_opts.index(prev_meal) + 1
                        mc = st.selectbox("Kies je maaltijd", ["— kies —"] + meal_opts, index=default_ix, key=f"meal_{row['id']}")
                        meal_choice = None if mc == "— kies —" else mc

                if st.button("Bewaar mijn keuze", key=f"save_{row['id']}", type="primary"):
                    try:
                        signup_upsert(
                            activiteit_id=row["id"],
                            username=my_username or None,
                            lid_id=my_lid_id or None,
                            status=("yes" if status == "Ik kom" else "no"),
                            eating=eating,
                            meal_choice=meal_choice
                        )
                        st.success("Inschrijving bijgewerkt.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Opslaan mislukt: {e}")

            # Print/Export per activiteit
            st.markdown("---")
            st.markdown("**Afdrukvoorbeeld / export van inschrijvingen**")
            print_df = s[["username", "status", "eating", "meal_choice", "signup_ts"]].copy()
            print_df = print_df.rename(columns={
                "username": "Gebruiker",
                "status": "Status",
                "eating": "Eet mee",
                "meal_choice": "Maaltijd",
                "signup_ts": "Ingeschreven op"
            })
            if not print_df.empty:
                print_df["Ingeschreven op"] = pd.to_datetime(print_df["Ingeschreven op"]).dt.strftime("%d/%m/%Y %H:%M")
            st.dataframe(print_df, use_container_width=True, hide_index=True)
            buf = io.BytesIO()
            print_df.to_csv(buf, index=False)
            st.download_button(
                "⬇️ Download CSV van inschrijvingen",
                data=buf.getvalue(),
                file_name=f"inschrijvingen_{row['titel']}_{row['datum']}.csv",
                mime="text/csv",
                key=f"csv_{row['id']}"
            )
            st.caption("Tip: gebruik je browser-print (Ctrl/Cmd + P) op deze pagina voor papier/PDF.")

    # ──────────────────────────────────────────────────────────────────────────
    # ADMIN: activiteiten verwijderen (toekomstige)
    # ──────────────────────────────────────────────────────────────────────────
    if current_role() == "admin":
        st.divider()
        st.subheader("Activiteiten verwijderen")
        df_del = activiteiten_list_df(upcoming=True).sort_values(["datum", "tijd"], na_position="last")
        if df_del.empty:
            st.caption("Geen toekomstige activiteiten.")
        else:
            options, id_map = [], {}
            for _, r in df_del.iterrows():
                datum_str = pd.to_datetime(r["datum"]).strftime("%d/%m/%Y")
                tijd_str = f" · {r['tijd']}" if r.get("tijd") else ""
                loc_str = f" · {r['locatie']}" if r.get("locatie") else ""
                label = f"{datum_str}{tijd_str} · {r['titel']}{loc_str}"
                options.append(label)
                id_map[label] = r["id"]

            sel_labels = st.multiselect("Selecteer activiteiten om te verwijderen", options, key="del_act_sel")
            if st.button("Verwijder geselecteerde activiteiten", key="del_act_btn", type="primary",
                         disabled=is_readonly() or not sel_labels):
                ids = [id_map[lbl] for lbl in sel_labels if lbl in id_map]
                if not ids:
                    st.warning("Niets geselecteerd.")
                else:
                    try:
                        run_db(lambda c: c.table("activiteiten").delete().in_("id", ids).execute(),
                        what="activiteiten delete")

                        st.success(f"Verwijderd: {len(ids)} activiteit(en).")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Verwijderen mislukt: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Wekelijkse mail preview/export (eerstvolgende 4)
    # ──────────────────────────────────────────────────────────────────────────
    st.divider()
    st.subheader("Wekelijkse mail — eerstvolgende 4 activiteiten")
    st.caption("Gebruik als preview/export. Voor automatisch versturen op maandag 08:00 heb je een scheduler nodig.")
    df2 = activiteiten_list_df(upcoming=True).sort_values(["datum", "tijd"], na_position="last").head(4)
    if df2.empty:
        st.info("Geen komende activiteiten.")
    else:
        view = df2[["titel", "datum", "tijd", "locatie"]].copy()
        view["datum"] = pd.to_datetime(view["datum"]).dt.strftime("%d/%m/%Y")
        st.dataframe(view, use_container_width=True, hide_index=True)
        out = io.BytesIO()
        view.to_csv(out, index=False)
        st.download_button(
            "⬇️ Exporteer CSV (mailbijlage)",
            data=out.getvalue(),
            file_name="weekmail_activiteiten.csv",
            mime="text/csv",
            key="weekmail_csv"
        )


def page_duiken():
    require_role("admin", "user")
    if is_readonly():
        st.warning("Read-only modus actief — opslaan uitgeschakeld.")

    appbar("duiken")
    st.header("Duiken invoeren")

    labels = duikers_labels()  # alleen duikers
    plaatsen = plaatsen_list()

    datum = st.date_input("Datum", datetime.date.today())
    duikcode = st.text_input("Duikcode (optioneel)")
    plaats = st.selectbox("Duikplaats", ["— kies —"] + plaatsen, index=0)
    sel_duikers = st.multiselect("Duikers", labels)

    # Admin mag hier ook meteen een nieuwe duikplaats toevoegen (met unieke keys)
    if current_role() == "admin":
        with st.expander("➕ Duikplaats toevoegen"):
            np2 = st.text_input("Nieuwe duikplaats", key="np_duiken")
            if st.button("Toevoegen", key="add_place_duiken"):
                if np2 and np2 not in plaatsen:
                    try:
                        plaats_add(np2)
                        st.success("Duikplaats toegevoegd.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Mislukt: {e}")
                else:
                    st.warning("Leeg of al bestaand.")

    if st.button(
        "Opslaan duik(en)",
        type="primary",
        disabled=(not sel_duikers or plaats == "— kies —" or is_readonly())
    ):
        rows = [
            {
                "datum": datum.isoformat(),
                "plaats": plaats,
                "duiker": label.replace(", ", " "),
                "duikcode": duikcode or ""
            }
            for label in sel_duikers
        ]
        try:
            duiken_insert(rows)
            st.success(f"{len(rows)} duik(en) opgeslagen.")
        except Exception as e:
            st.error(f"Opslaan mislukt: {e}")


def page_overzicht():
    require_role("admin","user")
    appbar("overzicht")
    st.header("Overzicht duiken")

    df = duiken_fetch_df()
    if df.empty:
        st.info("Nog geen duiken.")
        return

    # Alleen duikers (veiligheidsnet)
    allowed_duiker_names = set([l.replace(", ", " ") for l in duikers_labels()])
    df = df[df["duiker"].isin(allowed_duiker_names)]

    if "id" not in df.columns:
        st.warning("Kolom 'id' ontbreekt in 'duiken' — verwijderen werkt niet.")
        df["id"] = None

    df["Datum"] = pd.to_datetime(df["datum"]).dt.date
    df["Plaats"] = df["plaats"]
    df["Duiker"] = df["duiker"]
    df["Duikcode"] = df["duikcode"].fillna("")

    c1, c2, c3, c4 = st.columns([1,1,1,2])
    min_d, max_d = df["Datum"].min(), df["Datum"].max()
    rng = c1.date_input("Periode", (min_d, max_d))
    pf = c2.selectbox("Duikplaats", ["Alle"] + sorted(df["Plaats"].dropna().unique().tolist()), index=0)
    cf = c3.selectbox("Duikcode", ["Alle"] + sorted([c if c else "—" for c in df["Duikcode"].unique().tolist()]), index=0)
    duikers = ["Alle"] + sorted(df["Duiker"].dropna().unique().tolist())
    dfilt = c4.selectbox("Duiker", duikers, index=0)

    start, end = rng if isinstance(rng, tuple) else (min_d, max_d)
    f = df[(df["Datum"] >= start) & (df["Datum"] <= end)].copy()
    if pf != "Alle":
        f = f[f["Plaats"] == pf]
    if cf != "Alle":
        f = f[f["Duikcode"].replace({"": "—"}) == cf]
    if dfilt != "Alle":
        f = f[f["Duiker"] == dfilt]
    f = f.sort_values(["Datum","Plaats","Duikcode","Duiker","id"]).reset_index(drop=True)

    view = f[["Datum","Plaats","Duiker","Duikcode"]].copy()
    view["Datum"] = pd.to_datetime(view["Datum"]).dt.strftime("%d/%m/%Y")
    st.dataframe(view, use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Duiken verwijderen (huidige filter)")
    options, id_map = [], {}
    f2 = f.copy(); f2["Datum"] = pd.to_datetime(f2["Datum"]).dt.date
    for _, r in f2.iterrows():
        dc = r.get("Duikcode") or r.get("duikcode") or ""
        dc = dc if dc else "—"
        label = f"{r['Datum'].strftime('%d/%m/%Y')} · {r['Plaats']} · {r['Duiker']} · {dc}"
        lbl = label if label not in id_map else f"{label}  (#ID:{r['id']})"
        options.append(lbl); id_map[lbl] = r["id"]
    sel = st.multiselect("Selecteer te verwijderen duiken", options)
    if st.button("Verwijder geselecteerde", disabled=(len(sel)==0)):
        ids = [id_map[x] for x in sel if id_map[x] is not None]
        if not ids:
            st.warning("Geen geldige ID's.")
        else:
            try:
                duiken_delete_by_ids(ids); st.success(f"Verwijderd: {len(ids)} duik(en)."); st.rerun()
            except Exception as e:
                st.error(f"Verwijderen mislukt: {e}")

    st.divider()
    st.subheader("Export (Excel)")
    out = io.BytesIO()
    with pd.ExcelWriter(out, engine="openpyxl") as w:
        view.to_excel(w, index=False, sheet_name="Duiken")
    st.download_button("⬇️ Download Excel", data=out.getvalue(), file_name="duiken_export.xlsx",
                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

def page_afrekening():
    # viewer mag bekijken; user/admin mogen registreren
    require_role("admin","user","viewer")
    appbar("afrekening")
    st.header("Afrekening")

    df = duiken_fetch_df()
    if df.empty:
        st.info("Nog geen duiken.")
        return

    # Alleen duikers tellen mee
    allowed_duiker_names = set([l.replace(", ", " ") for l in duikers_labels()])
    df = df[df["duiker"].isin(allowed_duiker_names)]
    if df.empty:
        st.info("Er zijn nog geen duiken voor geregistreerde duikers.")
        return

    df["Datum"] = pd.to_datetime(df["datum"]).dt.date
    df["Plaats"] = df["plaats"]; df["Duiker"] = df["duiker"]

    c1, c2, c3, c4 = st.columns(4)
    min_d, max_d = df["Datum"].min(), df["Datum"].max()
    rng = c1.date_input("Periode", (min_d, max_d))
    bedrag = c2.number_input("Bedrag per duik (€)", min_value=0.0, step=0.5, value=5.0)
    pf = c3.selectbox("Duikplaats (optioneel)", ["Alle"] + sorted(df["Plaats"].dropna().unique().tolist()), index=0)
    blok = c4.number_input("Blokgrootte (€)", min_value=0.0, step=10.0, value=30.0)

    start, end = rng if isinstance(rng, tuple) else (min_d, max_d)
    m = (df["Datum"] >= start) & (df["Datum"] <= end)
    if pf != "Alle":
        m &= df["Plaats"] == pf
    s = df.loc[m].copy()
    if s.empty:
        st.warning("Geen duiken in de gekozen periode/filters.")
        return

    per = s.groupby("Duiker").size().reset_index(name="AantalDuiken")
    per["Bruto"] = (per["AantalDuiken"] * bedrag).round(2)

    # Restsaldo ophalen uit duikers indien beschikbaar
    try:
        ddf = run_db(lambda c: c.table("duikers").select("voornaam, achternaam, naam, rest_saldo").execute(),
                     what="duikers join").data or []
        ddf = pd.DataFrame(ddf)
    except Exception:
        ddf = pd.DataFrame([])

    vns, ans, rests = [], [], []
    for disp in per["Duiker"].astype(str).tolist():
        vn, an, rest = "", "", 0.0
        if not ddf.empty:
            row = ddf.loc[ddf["naam"] == disp]
            if not row.empty:
                vn = (row.iloc[0].get("voornaam") or "").strip()
                an = (row.iloc[0].get("achternaam") or "").strip()
                rest = float(row.iloc[0].get("rest_saldo") or 0)
            else:
                parts = disp.split()
                if parts:
                    vn = parts[0]; an = " ".join(parts[1:])
                row2 = ddf.loc[(ddf["voornaam"].fillna("").str.strip()==vn) & (ddf["achternaam"].fillna("").str.strip()==an)]
                if not row2.empty:
                    rest = float(row2.iloc[0].get("rest_saldo") or 0)
        else:
            parts = disp.split()
            if parts:
                vn = parts[0]; an = " ".join(parts[1:])
        vns.append(vn); ans.append(an); rests.append(round(float(rest),2))

    per["Voornaam"]=vns; per["Achternaam"]=ans; per["RestOud"]=rests
    per["Totaal"]=(per["Bruto"]+per["RestOud"]).round(2)

    def calc_blokken(total: float):
        if blok <= 0: return 0, 0.0, round(total, 2)
        n = math.floor(total / blok)
        uit = round(n * blok, 2)
        rest = round(total - uit, 2)
        return n, uit, rest

    rows=[]
    for _, r in per.iterrows():
        n, uit, rest = calc_blokken(float(r["Totaal"]))
        rows.append({**r.to_dict(), "Blokken": n, "UitTeBetalen": uit, "RestNieuw": rest})
    per = pd.DataFrame(rows).sort_values(["Achternaam","Voornaam","Duiker"], na_position="last").reset_index(drop=True)

    st.subheader("Afrekening per duiker")
    show_cols = ["Achternaam","Voornaam","AantalDuiken","Bruto","RestOud","Totaal","Blokken","UitTeBetalen","RestNieuw"]
    st.dataframe(per[show_cols], use_container_width=True, hide_index=True)

    # viewer: alleen kijken; user/admin mogen registreren
    if current_role() in {"admin","user"} and not is_readonly():
        st.divider(); st.subheader("Markeer als betaald / update restsaldo")
        per["select"]=False
        for i in range(len(per)):
            label=f"{per.at[i,'Achternaam']}, {per.at[i,'Voornaam']}"
            per.at[i,"select"]=st.checkbox(label, key=f"sel_pay_{i}")
        if st.button("Markeer geselecteerde als betaald"):
            try:
                sel = per[per["select"]==True]
                if sel.empty:
                    st.warning("Geen duikers geselecteerd.")
                else:
                    for _, r in sel.iterrows():
                        row = {
                            "voornaam": (r["Voornaam"] or "").strip(),
                            "achternaam": (r["Achternaam"] or "").strip(),
                            "periode_start": start,
                            "periode_end": end,
                            "bedrag_per_duik": float(bedrag),
                            "blokgrootte": float(blok),
                            "aantal_duiken": int(r["AantalDuiken"]),
                            "bruto_bedrag": float(r["Bruto"]),
                            "rest_oud": float(r["RestOud"]),
                            "blokken": int(r["Blokken"]),
                            "uit_te_betalen": float(r["UitTeBetalen"]),
                            "rest_nieuw": float(r["RestNieuw"]),
                            "betaald_op": dt.utcnow().isoformat()
                        }
                        afrekening_insert(row)
                        # update restsaldo in duikers
                        if row["voornaam"] or row["achternaam"]:
                            run_db(lambda c: c.table("duikers").update({"rest_saldo": float(r["RestNieuw"])}).eq("voornaam", row["voornaam"]).eq("achternaam", row["achternaam"]).execute(),
                                   what="duikers update rest")
                    st.success("Afrekening geregistreerd."); st.rerun()
            except Exception as e:
                st.error(f"Registratie mislukt: {e}")

def page_beheer():
    require_role("admin")
    appbar("beheer")
    st.header("Beheer")
    tabs = st.tabs(["Ledenbeheer", "Duikers", "Duikplaatsen", "Back-up/Export"])

    with tabs[0]:
        page_ledenbeheer()

    with tabs[1]:
        res = run_db(
            lambda c: c.table("duikers").select("voornaam, achternaam, naam, rest_saldo").execute(),
            what="duikers select (beheer)"
        )
        ddf = pd.DataFrame(res.data or [])
        st.subheader("Duikers (afgeleid uit leden met duikbrevet)")
        if not ddf.empty:
            view = ddf.rename(
                columns={"voornaam": "Voornaam", "achternaam": "Achternaam", "rest_saldo": "Rest (start)"}
            )
            st.dataframe(view, use_container_width=True, hide_index=True)
        else:
            st.caption("Nog geen duikers — geef duikbrevet aan een lid in Ledenbeheer.")

    with tabs[2]:
        st.subheader("Duikplaatsen")
        pl = plaatsen_list()
        st.dataframe(pd.DataFrame({"Plaats": pl}), use_container_width=True, hide_index=True)

        np = st.text_input("Nieuwe duikplaats", key="np_beheer")
        if st.button("Toevoegen", key="add_place_beheer", disabled=is_readonly()):
            if np and np not in pl:
                try:
                    plaats_add(np)
                    st.success("Duikplaats toegevoegd.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Mislukt: {e}")
            else:
                st.warning("Leeg of al bestaand.")

    with tabs[3]:
        st.subheader("Back-up (Excel)")
        if st.button("Maak back-up"):
            out = io.BytesIO()
            duikers = run_db(lambda c: c.table("duikers").select("*").execute(), what="duikers select (backup)")
            plaatsen_df = run_db(lambda c: c.table("duikplaatsen").select("*").execute(), what="duikplaatsen select (backup)")
            duiken = run_db(lambda c: c.table("duiken").select("*").execute(), what="duiken select (backup)")
            leden = run_db(lambda c: c.table("leden").select("*").execute(), what="leden select (backup)")
            df_duikers = pd.DataFrame(duikers.data or [])
            df_plaatsen = pd.DataFrame(plaatsen_df.data or [])
            df_duiken = pd.DataFrame(duiken.data or [])
            df_leden = pd.DataFrame(leden.data or [])
            stamp = dt.utcnow().strftime("%Y%m%d_%H%M%S")
            with pd.ExcelWriter(out, engine="openpyxl") as w:
                df_duikers.to_excel(w, index=False, sheet_name="duikers")
                df_plaatsen.to_excel(w, index=False, sheet_name="duikplaatsen")
                df_duiken.to_excel(w, index=False, sheet_name="duiken")
                df_leden.to_excel(w, index=False, sheet_name="leden")
            st.download_button(
                "⬇️ Download back-up",
                data=out.getvalue(),
                file_name=f"anww_backup_{stamp}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )

# ──────────────────────────────────────────────────────────────────────────────
# MAIN — na login meteen Activiteiten
# ──────────────────────────────────────────────────────────────────────────────
def main():
    # 0) Eerste admin?
    try:
        if auth_count_admins() == 0 and "auth_user" not in st.session_state:
            page_setup_first_admin_username()
            return
    except Exception:
        st.error("Tabel 'auth_local' ontbreekt. Voer de 1-klik SQL eerst uit.")
        st.stop()

    # 1) Niet ingelogd → login
    if "auth_user" not in st.session_state:
        page_login_username()
        return

    role = current_role()
    # Activiteiten als eerste pagina
    if role == "admin":
        tabs = st.tabs(["Activiteiten","Duiken invoeren","Overzicht","Afrekening","Beheer","Mijn profiel"])
        with tabs[0]: page_activiteiten()
        with tabs[1]: page_duiken()
        with tabs[2]: page_overzicht()
        with tabs[3]: page_afrekening()
        with tabs[4]: page_beheer()
        with tabs[5]: page_profiel()
    elif role == "user":
        tabs = st.tabs(["Activiteiten","Duiken invoeren","Overzicht","Afrekening","Mijn profiel"])
        with tabs[0]: page_activiteiten()
        with tabs[1]: page_duiken()
        with tabs[2]: page_overzicht()
        with tabs[3]: page_afrekening()
        with tabs[4]: page_profiel()
    elif role == "member":
        tabs = st.tabs(["Activiteiten","Mijn profiel"])
        with tabs[0]: page_activiteiten()
        with tabs[1]: page_profiel()
    else:  # viewer
        tabs = st.tabs(["Afrekening","Mijn profiel"])
        with tabs[0]: page_afrekening()
        with tabs[1]: page_profiel()

if __name__ == "__main__":
    st.markdown("<div style='color:red;'>CSS test geladen</div>", unsafe_allow_html=True)

    main()

