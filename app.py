# app.py — ANWW Duikapp (schone basis)
# Build: v2025-10-03-LOCAL-AUTH-CLEAN

import streamlit as st
import pandas as pd
import datetime
from datetime import datetime as dt
import io
import os
import time
import math
import hmac, hashlib, secrets
from typing import Optional
from supabase import create_client, Client
from postgrest.exceptions import APIError
import httpx

# ──────────────────────────────────────────────────────────────────────────────
# App config & styling
# ──────────────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="ANWW Duikapp", layout="wide")
APP_BUILD = "v2025-10-03-LOCAL-AUTH-CLEAN"

def _inject_css():
    st.markdown("""
    <style>
      .badge {border:1px solid #e5e7eb;padding:4px 10px;border-radius:999px;background:#fff;}
      .stButton > button{border-radius:10px;}
    </style>
    """, unsafe_allow_html=True)
_inject_css()

def is_readonly() -> bool:
    # Zet [app].force_readonly = true in secrets.toml om tijdelijk schrijven te blokkeren
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
# Lokale AUTH (auth_local): e-mail + wachtwoordhash + rol
# ──────────────────────────────────────────────────────────────────────────────
# Hashformaat: "pbkdf2$<iters>$<salt_hex>$<hash_hex>"
def _hash_password(password: str, iterations: int = 240000) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2${iterations}${salt.hex()}${dk.hex()}"

def _verify_password(password: str, hashed: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = hashed.split("$", 3)
        if algo != "pbkdf2":
            return False
        iters = int(iters)
        salt = bytes.fromhex(salt_hex)
        ref = bytes.fromhex(hash_hex)
        test = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
        return hmac.compare_digest(ref, test)
    except Exception:
        return False

def auth_get_user_by_email(email: str) -> Optional[dict]:
    email = (email or "").strip().lower()
    if not email:
        return None
    res = run_db(lambda c: c.table("auth_local").select("*").eq("email", email).limit(1).execute(),
                 what="auth_local select by email")
    rows = res.data or []
    return rows[0] if rows else None

def auth_count_admins() -> int:
    res = run_db(lambda c: c.table("auth_local").select("id", count="exact").eq("role","admin").execute(),
                 what="auth_local count admin")
    return res.count or 0

def auth_create_user(email: str, password: str, role: str, username: str | None = None):
    if is_readonly():
        raise Exception("Read-only modus")
    email = (email or "").strip().lower()
    role = (role or "viewer").strip().lower()
    if role not in {"admin","user","member","viewer"}:
        role = "viewer"
    payload = {
        "email": email,
        "password_hash": _hash_password(password),
        "role": role,
        "username": (username or "").strip() or None
    }
    run_db(lambda c: c.table("auth_local").insert(payload).execute(),
           what="auth_local insert")

def auth_update_password(email: str, new_pw: str):
    if is_readonly():
        raise Exception("Read-only modus")
    email = (email or "").strip().lower()
    run_db(lambda c: c.table("auth_local").update({"password_hash": _hash_password(new_pw)}).eq("email", email).execute(),
           what="auth_local update password")

def current_user():
    return st.session_state.get("auth_user") or {}

def current_role() -> str:
    u = current_user()
    r = (u.get("role") or "viewer").lower()
    return r if r in {"admin","user","member","viewer"} else "viewer"

def current_email() -> str:
    return (current_user().get("email") or "").lower().strip()

def current_username() -> str:
    # voorkeur: auth_local.username → leden.username
    u = current_user()
    if u.get("username"):
        return u.get("username")
    try:
        res = run_db(lambda c: c.table("leden").select("username").eq("email", current_email()).limit(1).execute(),
                     what="leden username by email")
        rows = res.data or []
        if rows and rows[0].get("username"):
            return rows[0]["username"]
    except Exception:
        pass
    return ""

# ──────────────────────────────────────────────────────────────────────────────
# Data helpers
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
    res = run_db(lambda c: c.table("leden").select("*").eq("email", email).limit(1).execute(),
                 what="leden select by email")
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
    expected = ["id","activiteit_id","username","lid_id","status","eating","meal_choice","signup_ts"]
    for col in expected:
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

def leden_van_username(username: str):
    if not username:
        return None
    try:
        res = run_db(lambda c: c.table("leden").select("*").eq("username", username).limit(1).execute(),
                     what="leden by username")
        rows = res.data or []
        return rows[0] if rows else None
    except Exception:
        return None

# ──────────────────────────────────────────────────────────────────────────────
# UI helpers
# ──────────────────────────────────────────────────────────────────────────────
def appbar(tag: str):
    col1, col2, col3 = st.columns([5, 3, 2])
    with col1:
        st.markdown("**ANWW Duikapp**")
    with col2:
        st.markdown(f"<div class='badge'>{current_username() or current_email() or '—'} · {current_role()} · Build {APP_BUILD}</div>",
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
def page_setup_first_admin():
    st.title("Eerste admin aanmaken")
    st.info("Er bestaat nog geen admin. Maak eerst de eerste admin aan.")
    with st.form("first_admin"):
        email = st.text_input("E-mail (login)", placeholder="naam@voorbeeld.be")
        pw1 = st.text_input("Wachtwoord", type="password")
        pw2 = st.text_input("Herhaal wachtwoord", type="password")
        username = st.text_input("Gebruikersnaam (optioneel)")
        submitted = st.form_submit_button("Maak admin", type="primary")
    if submitted:
        if not email or not pw1 or len(pw1) < 8 or pw1 != pw2:
            st.error("Controleer e-mail en wachtwoord (min. 8 tekens en gelijk).")
            return
        try:
            auth_create_user(email, pw1, "admin", username=username or None)
            leden_upsert({
                "email": email.lower().strip(),
                "voornaam": "",
                "achternaam": "",
                "username": username or None,
                "role": "admin",
                "opt_in_weekly": True,
                "actief": True
            })
            st.success("Admin aangemaakt. Je kan nu inloggen.")
            st.session_state["just_created_admin"] = True
        except Exception as e:
            st.error(f"Mislukt: {e}")

def page_login():
    st.title("Inloggen")
    if st.session_state.get("just_created_admin"):
        st.success("Admin aangemaakt. Log nu in.")
        st.session_state.pop("just_created_admin", None)

    with st.form("login_form"):
        email = st.text_input("E-mail")
        pw = st.text_input("Wachtwoord", type="password")
        submitted = st.form_submit_button("Login", type="primary")
    if not submitted:
        return
    user = auth_get_user_by_email(email)
    if not user or not _verify_password(pw, user.get("password_hash") or ""):
        st.error("Onjuiste login.")
        return
    u = {"id": user.get("id"), "email": user.get("email"), "role": user.get("role"), "username": user.get("username")}
    if not u.get("username"):
        try:
            row = leden_get_by_email(u["email"])
            if row and row.get("username"):
                u["username"] = row["username"]
        except Exception:
            pass
    st.session_state["auth_user"] = u
    st.success("Ingelogd.")
    st.rerun()

def page_profiel():
    appbar("profiel")
    st.header("Mijn profiel")
    u = current_user()
    st.write(f"**E-mail:** {u.get('email')}")
    st.write(f"**Rol:** {u.get('role')}")
    st.write(f"**Gebruikersnaam:** {current_username() or '—'}")

    st.divider()
    st.subheader("Wekelijkse mail")
    row = leden_get_by_email(current_email())
    cur_opt = bool((row or {}).get("opt_in_weekly", True))
    new_opt = st.toggle("Ik wil de wekelijkse activiteitenmail ontvangen", value=cur_opt)
    if st.button("Bewaar voorkeur"):
        try:
            leden_upsert({ "email": current_email(), "opt_in_weekly": bool(new_opt) })
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
                auth_update_password(current_email(), npw1)
                st.success("Wachtwoord gewijzigd.")
            except Exception as e:
                st.error(f"Mislukt: {e}")

def page_ledenbeheer():
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
            email = st.text_input("E-mail (login)")
        with c2:
            username = st.text_input("Login (username)")
            role = st.selectbox("Rol/functie", options=ROLE_CHOICES, index=2)  # default member
        with c3:
            brevet = st.selectbox("Duikbrevet", options=["(geen)"] + BREVET_CHOICES, index=0)
            optin = st.toggle("Wekelijkse mail", value=True)
            actief = st.toggle("Actief", value=True)
        pw1 = st.text_input("Initieel wachtwoord (alleen bij 1e keer toevoegen)", type="password")
        pw2 = st.text_input("Herhaal wachtwoord", type="password")
        submitted = st.form_submit_button("Bewaar lid", type="primary")

    if submitted:
        if not email:
            st.warning("E-mail is verplicht (loginnaam)."); return
        payload = {
            "email": email.strip().lower(),
            "voornaam": (vn or "").strip(),
            "achternaam": (an or "").strip(),
            "username": (username or "").strip() or None,
            "role": role,
            "duikbrevet": None if brevet == "(geen)" else brevet,
            "opt_in_weekly": bool(optin),
            "actief": bool(actief)
        }
        try:
            # 1) leden upsert
            leden_upsert(payload)
            # 2) login aanmaken/bijwerken in auth_local
            u = auth_get_user_by_email(email)
            if not u:
                if not pw1 or len(pw1) < 8 or pw1 != pw2:
                    st.warning("Nieuwe login vereist wachtwoord (min. 8 tekens) en beide velden gelijk.")
                    return
                auth_create_user(email, pw1, role, username=payload["username"])
            else:
                if not is_readonly():
                    run_db(lambda c: c.table("auth_local").update({
                        "role": role,
                        "username": payload["username"]
                    }).eq("email", email.strip().lower()).execute(), what="auth_local update")
            st.success("Lid + login bewaard."); st.rerun()
        except Exception as e:
            st.error(f"Bewaren mislukt: {e}")

    st.divider()
    st.subheader("Login resetten (nieuw wachtwoord zetten)")
    with st.form("reset_pw"):
        email2 = st.text_input("E-mail van lid")
        npw1 = st.text_input("Nieuw wachtwoord", type="password")
        npw2 = st.text_input("Herhaal nieuw wachtwoord", type="password")
        ok = st.form_submit_button("Zet nieuw wachtwoord")
    if ok:
        if not email2 or not npw1 or len(npw1) < 8 or npw1 != npw2:
            st.warning("Controleer e-mail en wachtwoord (min. 8 tekens, gelijk).")
        else:
            try:
                if not auth_get_user_by_email(email2):
                    st.warning("Er bestaat nog geen login voor dit e-mailadres. Maak eerst het lid (met initieel wachtwoord).")
                else:
                    auth_update_password(email2, npw1)
                    st.success("Wachtwoord gereset.")
            except Exception as e:
                st.error(f"Reset mislukt: {e}")

def page_activiteiten():
    require_role("admin","user","member","viewer")  # iedereen kijkt; inschrijven: admin/user/member
    if is_readonly():
        st.warning("Read-only modus actief — inschrijven kan geblokkeerd zijn.")
    appbar("activiteiten")
    st.header("Kalender & Inschrijvingen")

    # Admin: activiteit toevoegen
    if current_role() == "admin":
        with st.expander("➕ Nieuwe activiteit"):
            c1, c2 = st.columns([2,1])
            with c1:
                titel = st.text_input("Titel*")
                omschr = st.text_area("Omschrijving")
            with c2:
                datum = st.date_input("Datum*", value=datetime.date.today())
                tijd = st.time_input("Tijd (optioneel)", value=None)
                locatie = st.text_input("Locatie")
            st.caption("Maaltijdopties (max. 3, optioneel)")
            m1, m2, m3 = st.columns(3)
            with m1: mo1 = st.text_input("Optie 1")
            with m2: mo2 = st.text_input("Optie 2")
            with m3: mo3 = st.text_input("Optie 3")
            if st.button("Activiteit toevoegen", type="primary"):
                if not titel or not datum:
                    st.warning("Titel en datum zijn verplicht.")
                else:
                    meal_opts = [x.strip() for x in [mo1, mo2, mo3] if x and x.strip()]
                    try:
                        activiteit_add(titel, omschr, datum, tijd, locatie, meal_opts or None, created_by=current_username() or current_email())
                        st.success("Activiteit aangemaakt."); st.rerun()
                    except Exception as e:
                        st.error(f"Mislukt: {e}")

    # Overzicht
    df = activiteiten_list_df(upcoming=True)
    if df.empty:
        st.info("Geen (toekomstige) activiteiten.")
        return

    my_user = current_user()
    my_username = current_username() or my_user.get("username")
    my_lid = leden_van_username(my_username) if my_username else leden_get_by_email(current_email())
    my_lid_id = (my_lid or {}).get("id")

    for _, row in df.sort_values(["datum","tijd"], na_position="last").iterrows():
        s = signups_get(row["id"])
        # bepaal mijn status
        myrow = None
        if my_username:
            tmp = s.loc[s["username"] == my_username]
            if not tmp.empty: myrow = tmp
        if (myrow is None or myrow.empty) and my_lid_id:
            tmp = s.loc[s["lid_id"] == my_lid_id]
            if not tmp.empty: myrow = tmp
        my_status = (myrow.iloc[0]["status"] if (myrow is not None and not myrow.empty) else None)
        badge = "🟢 ingeschreven" if my_status == "yes" else ("🔴 niet ingeschreven" if my_status == "no" else "⚪ nog niet gekozen")

        titel = f"{row['titel']} — {pd.to_datetime(row['datum']).strftime('%d/%m/%Y')}"
        if row.get("tijd"):
            titel += f" · {row['tijd']}"

        with st.expander(f"{titel}   ·   {badge}", expanded=False):
            if row.get("locatie"): st.caption(row["locatie"])
            if row.get("omschrijving"): st.write(row["omschrijving"])

            # Lijsten, gesorteerd op inschrijfmoment
            coming = s.loc[s["status"]=="yes"].sort_values("signup_ts")
            notcoming = s.loc[s["status"]=="no"].sort_values("signup_ts")

            colA, colB = st.columns(2)
            with colA:
                st.markdown("**Komen (op volgorde van inschrijving):**")
                if coming.empty: st.caption("Nog niemand.")
                else:
                    for _, ss in coming.iterrows():
                        meal = f" · eet: {ss['meal_choice']}" if ss.get("eating") else ""
                        st.write(f"- {ss.get('username') or 'lid'}{meal}")
            with colB:
                st.markdown("**Niet komen:**")
                if notcoming.empty: st.caption("Nog niemand.")
                else:
                    for _, ss in notcoming.iterrows():
                        st.write(f"- {ss.get('username') or 'lid'}")

            # Inschrijven — alleen admin/user/member (viewer ziet enkel lijsten)
            if current_role() in {"admin","user","member"}:
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

                if st.button("Bewaar mijn keuze", key=f"save_{row['id']}", type="primary", disabled=is_readonly()):
                    try:
                        signup_upsert(
                            activiteit_id=row["id"],
                            username=my_username or None,
                            lid_id=my_lid_id or None,
                            status=("yes" if status == "Ik kom" else "no"),
                            eating=eating,
                            meal_choice=meal_choice
                        )
                        st.success("Inschrijving bijgewerkt."); st.rerun()
                    except Exception as e:
                        st.error(f"Opslaan mislukt: {e}")

    st.divider()
    st.subheader("Wekelijkse mail — eerstvolgende 4 activiteiten")
    st.caption("Gebruik dit als preview/export. Voor automatisch uitsturen op maandag 08:00 heb je een scheduler nodig (bv. Edge Function + cron).")
    df2 = activiteiten_list_df(upcoming=True).sort_values(["datum","tijd"], na_position="last").head(4)
    if df2.empty:
        st.info("Geen komende activiteiten.")
    else:
        view = df2[["titel","datum","tijd","locatie"]].copy()
        view["datum"] = pd.to_datetime(view["datum"]).dt.strftime("%d/%m/%Y")
        st.dataframe(view, use_container_width=True, hide_index=True)
        out = io.BytesIO()
        view.to_csv(out, index=False)
        st.download_button("⬇️ Exporteer CSV (mailbijlage)", data=out.getvalue(), file_name="weekmail_activiteiten.csv", mime="text/csv")

def page_duiken():
    require_role("admin","user")
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

    if current_role() == "admin":
        with st.expander("➕ Duikplaats toevoegen"):
            np = st.text_input("Nieuwe duikplaats")
            if st.button("Toevoegen"):
                if np and np not in plaatsen:
                    try:
                        plaats_add(np); st.success("Duikplaats toegevoegd."); st.rerun()
                    except Exception as e:
                        st.error(f"Mislukt: {e}")
                else:
                    st.warning("Leeg of al bestaand.")

    if st.button("Opslaan duik(en)", type="primary", disabled=(not sel_duikers or plaats == "— kies —" or is_readonly())):
        rows = [{"datum": datum.isoformat(), "plaats": plaats, "duiker": lab.replace(", ", " "), "duikcode": duikcode or ""} for lab in sel_duikers]
        try:
            duiken_insert(rows); st.success(f"{len(rows)} duik(en) opgeslagen.")
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

    # Alleen duikers meetellen (veiligheidsnet)
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
    if pf != "Alle": f = f[f["Pla
