# app.py — ANWW Duikapp (robuste Supabase connectie + retry + nette errors)
import streamlit as st
from datetime import datetime as dt, timedelta
import datetime
import pandas as pd
import bcrypt
import io
import time
import json

from supabase import create_client, Client
from postgrest.exceptions import APIError
import httpx  # voor ConnectError/ReadTimeout

APP_BUILD = "v2025-09-13-ANWW-03+net-robust"

# ──────────────────────────────
# Basisconfig
# ──────────────────────────────
st.set_page_config(page_title="logo.png (Supabase)", layout="wide")

def secrets_healthcheck():
    secs = list(st.secrets.keys())
    st.caption(
        f"🩺 Secrets: Supabase {'✅' if 'supabase' in secs else '❌'} · "
        f"Theme {'✅' if 'theme' in secs else '❌'}"
    )
secrets_healthcheck()

# ──────────────────────────────
# THEMA
# ──────────────────────────────
THEME_DEFAULTS = {
    "bg": "#f7f9fc","surface": "#f0f4ff","card": "#ffffff","border": "#e5e7eb",
    "text": "#0f172a","muted": "#475569","primary": "#2563eb","primary_contrast": "#ffffff",
    "accent": "#38bdf8","success": "#16a34a","warning": "#f59e0b","error": "#ef4444",
}

def _merge_theme(defaults: dict, overrides: dict | None) -> dict:
    if not overrides: return defaults
    out = defaults.copy()
    for k,v in overrides.items():
        if isinstance(v, str) and v.strip():
            out[k] = v.strip()
    return out

def base_css() -> str:
    return """
    .appbar { display:flex; align-items:center; margin-bottom:8px; font-weight:600; }
    .appbar-left  { display:flex; align-items:center; gap:.5rem; }
    .appbar-mid   { display:flex; justify-content:center; }
    .appbar-right { display:flex; justify-content:flex-end; align-items:center; gap:.5rem; }
    .badge { border:1px solid var(--border); padding:4px 10px; border-radius:999px; font-size:0.9rem; background:var(--card); }
    """

def inject_theme():
    theme = _merge_theme(THEME_DEFAULTS, st.secrets.get("theme"))
    css_vars = f"""
    :root {{
      --bg:{theme['bg']}; --surface:{theme['surface']}; --card:{theme['card']}; --border:{theme['border']};
      --text:{theme['text']}; --muted:{theme['muted']};
      --primary:{theme['primary']}; --primary-contrast:{theme['primary_contrast']};
      --accent:{theme['accent']}; --success:{theme['success']}; --warning:{theme['warning']}; --error:{theme['error']};
    }}
    """
    page = """
    .stApp{ background: radial-gradient(1200px 800px at 20% 10%, var(--surface), var(--bg) 60%); color: var(--text); }
    .stButton > button{
        background: var(--primary) !important; color: var(--primary-contrast) !important;
        border: 1px solid var(--primary) !important; border-radius: 10px !important;
        box-shadow: 0 4px 14px rgba(0,0,0,.08) !important; transition: all .15s ease;
    }
    .stButton > button:hover{ filter:brightness(1.05); transform: translateY(-1px); }
    .stButton > button:disabled{ opacity:.5 !important; cursor:not-allowed !important; }
    .stTextInput input, .stNumberInput input, .stDateInput input,
    .stSelectbox > div > div, .stMultiSelect > div > div{
        background:var(--card)!important; color:var(--text)!important; border:1px solid var(--border)!important; border-radius:10px!important;
    }
    .stTabs [role="tab"]{ color:var(--muted); border-bottom:2px solid transparent; }
    .stTabs [role="tab"][aria-selected="true"]{ color:var(--text); border-bottom:2px solid var(--accent); }
    .stDataFrame thead tr th{ background: color-mix(in srgb, var(--card) 80%, var(--accent) 20%); color:var(--text); }
    .stAlert [role="alert"]{ border:1px solid var(--border); background:var(--card); color:var(--text); }
    """
    st.markdown(f"<style>{css_vars}{base_css()}{page}</style>", unsafe_allow_html=True)

inject_theme()

# ──────────────────────────────
# Supabase client (robust + connectivity check)
# ──────────────────────────────
@st.cache_resource
def get_client() -> Client:
    import os
    supa = st.secrets.get("supabase", {})
    url = supa.get("url") or os.getenv("SUPABASE_URL")
    key = supa.get("anon_key") or os.getenv("SUPABASE_ANON_KEY")

    missing = []
    if not url: missing.append("supabase.url (of SUPABASE_URL)")
    if not key: missing.append("supabase.anon_key (of SUPABASE_ANON_KEY)")
    if missing:
        st.error("Supabase configuratie ontbreekt:\n- " + "\n- ".join(missing))
        st.stop()

    # Client aanmaken
    try:
        client = create_client(url, key)
    except Exception as e:
        st.error(f"Kon Supabase client niet maken: {e}")
        st.stop()

    # Korte connectiviteitstest met kleine timeout/retry
    try:
        _probe_supabase(client)
    except Exception as e:
        st.error(
            "Kon geen netwerkverbinding maken met Supabase. Mogelijke oorzaken:\n"
            "- Verkeerde `supabase.url`\n- Tijdelijke netwerk/DNS/SSL-storing\n"
            "- Outbound internet hapering in hosting\n\nDetails: " + str(e)
        )
        st.stop()

    return client

def _probe_supabase(client: Client):
    # Probe: minimal select op een lichte system view of eigen tabellen.
    # We proberen users te vragen met limit(1); als de tabel niet bestaat is dat ook ok (we willen alleen netwerk).
    try:
        client.postgrest.auth.token  # touch to ensure auth is set
    except Exception:
        pass

    try:
        client.table("users").select("username").limit(1).execute()
    except APIError:
        # DB is bereikbaar (network ok), maar policy/structuur kan fout zijn: dat is geen netwerffout.
        return
    except (httpx.ConnectError, httpx.ReadTimeout) as e:
        raise RuntimeError(f"Network to Supabase failed: {e}") from e
    except Exception:
        # Andere errors negeren hier; belangrijkste is dat netwerk lukt of APIError terugkomt.
        return

sb = get_client()

# Helper: generieke retry voor DB-calls
def run_db(fn, *, tries=3, backoff=0.7, what="database call"):
    last_err = None
    for i in range(1, tries+1):
        try:
            return fn()
        except (httpx.ConnectError, httpx.ReadTimeout) as e:
            last_err = e
            if i < tries:
                time.sleep(backoff * i)
                continue
            st.error(f"Netwerkfout bij {what}: {e}")
            st.stop()
        except APIError as e:
            # Toon een duidelijke, maar niet-gevoelige melding
            st.error(
                f"API-fout bij {what}. Controleer of de tabel bestaat en of RLS/policies toegang geven "
                f"voor de anon key (select/insert/update waar nodig)."
            )
            st.caption(str(e))
            st.stop()
        except Exception as e:
            last_err = e
            if i < tries:
                time.sleep(backoff * i)
                continue
            st.error(f"Onverwachte fout bij {what}: {e}")
            st.stop()
    return None

# ──────────────────────────────
# Constants & "noodslot"
# ──────────────────────────────
MAX_ATTEMPTS = 5
LOCK_MINUTES = 15
ALLOWED_ROLES = {"admin", "user", "viewer"}
FORCE_READONLY = bool(st.secrets.get("app", {}).get("force_readonly", False))

# ──────────────────────────────
# Helpers: rollen / security
# ──────────────────────────────
def normalize_role(raw) -> str:
    r = (raw or "user").strip().lower()
    return r if r in ALLOWED_ROLES else "user"

def current_role() -> str:
    return normalize_role(st.session_state.get("role"))

def is_viewer_effective() -> bool:
    return FORCE_READONLY or (current_role() == "viewer")

def _ensure_not_viewer():
    if is_viewer_effective():
        raise Exception("Viewer/read-only modus: schrijven is geblokkeerd.")

# ──────────────────────────────
# DB helpers (allemaal via run_db)
# ──────────────────────────────
def get_user(username: str):
    return run_db(
        lambda: sb.table("users").select("*").eq("username", username).limit(1).execute(),
        what="users select",
    ).data and run_db(
        lambda: sb.table("users").select("*").eq("username", username).limit(1).execute(),
        what="users select (read)",
    ).data[0] or None

def list_admin_usernames() -> list[str]:
    res = run_db(lambda: sb.table("users").select("username, role").eq("role","admin").execute(), what="users (admins)")
    return [r["username"] for r in (res.data or [])]

def set_password(username: str, new_password: str):
    _ensure_not_viewer()
    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    run_db(lambda: sb.table("users").update({
        "password_hash": hashed, "failed_attempts": 0, "locked_until": None
    }).eq("username", username).execute(), what="users update (password)")

def update_user_role(username: str, new_role: str):
    _ensure_not_viewer()
    run_db(lambda: sb.table("users").update({"role": normalize_role(new_role)}).eq("username", username).execute(),
           what="users update (role)")

def clear_lock(username: str):
    _ensure_not_viewer()
    run_db(lambda: sb.table("users").update({"failed_attempts": 0, "locked_until": None}).eq("username", username).execute(),
           what="users update (clear lock)")

def register_failed_attempt(username: str):
    u = get_user(username)
    if not u:
        return 0, None
    attempts = int(u.get("failed_attempts") or 0) + 1
    if attempts >= MAX_ATTEMPTS:
        until = (dt.utcnow() + timedelta(minutes=LOCK_MINUTES)).isoformat()
        run_db(lambda: sb.table("users").update({"failed_attempts": 0, "locked_until": until}).eq("username", username).execute(),
               what="users update (lock)")
        return MAX_ATTEMPTS, until
    else:
        run_db(lambda: sb.table("users").update({"failed_attempts": attempts}).eq("username", username).execute(),
               what="users update (failed attempts)")
        return attempts, None

def is_locked(urow):
    lu = urow.get("locked_until")
    if not lu:
        return False, None
    try:
        if dt.utcnow() < dt.fromisoformat(lu.replace("Z","")):
            return True, lu
        return False, None
    except Exception:
        return False, None

def list_duikers() -> list[str]:
    res = run_db(lambda: sb.table("duikers").select("naam").order("naam").execute(), what="duikers select")
    return [r["naam"] for r in (res.data or [])]

def add_duiker(name: str):
    _ensure_not_viewer()
    run_db(lambda: sb.table("duikers").insert({"naam": name}).execute(), what="duikers insert")

def delete_duikers(names: list[str]) -> tuple[bool, int, str | None]:
    if not names: return True, 0, None
    try:
        _ensure_not_viewer()
        run_db(lambda: sb.table("duikers").delete().in_("naam", names).execute(), what="duikers delete")
        return True, len(names), None
    except Exception as e:
        return False, 0, str(e)

def list_plaatsen() -> list[str]:
    res = run_db(lambda: sb.table("duikplaatsen").select("plaats").order("plaats").execute(), what="duikplaatsen select")
    return [r["plaats"] for r in (res.data or [])]

def add_plaats(plaats: str):
    _ensure_not_viewer()
    run_db(lambda: sb.table("duikplaatsen").insert({"plaats": plaats}).execute(), what="duikplaatsen insert")

def delete_plaatsen(plaatsen: list[str]) -> tuple[bool, int, str | None]:
    if not plaatsen: return True, 0, None
    try:
        _ensure_not_viewer()
        run_db(lambda: sb.table("duikplaatsen").delete().in_("plaats", plaatsen).execute(), what="duikplaatsen delete")
        return True, len(plaatsen), None
    except Exception as e:
        return False, 0, str(e)

def save_duiken(rows):
    if rows:
        _ensure_not_viewer()
        run_db(lambda: sb.table("duiken").insert(rows).execute(), what="duiken insert")

def fetch_duiken(filters=None) -> pd.DataFrame:
    def _go():
        q = sb.table("duiken").select("*")
        if filters:
            for k, v in filters.items():
                if v is None: continue
                if k == "datum_eq": q = q.eq("datum", v)
                elif k == "plaats_eq": q = q.eq("plaats", v)
                elif k == "duikcode_eq": q = q.eq("duikcode", v)
                elif k == "datum_gte": q = q.gte("datum", v)
                elif k == "datum_lte": q = q.lte("datum", v)
                elif k == "duiker_eq": q = q.eq("duiker", v)
        return q.order("datum", desc=True).order("plaats").order("duikcode").order("duiker").execute()

    res = run_db(_go, what="duiken select")
    return pd.DataFrame(res.data or [])

def delete_duiken_by_ids(ids):
    if ids:
        _ensure_not_viewer()
        run_db(lambda: sb.table("duiken").delete().in_("id", ids).execute(), what="duiken delete")

def delete_users(usernames: list[str]) -> tuple[bool, int, str | None]:
    if not usernames: return True, 0, None
    try:
        _ensure_not_viewer()
        run_db(lambda: sb.table("users").delete().in_("username", usernames).execute(), what="users delete")
        return True, len(usernames), None
    except Exception as e:
        return False, 0, str(e)

def ensure_admin_exists():
    # maak admin / 1234 aan als die niet bestaat; vangt policies/netwerk netjes af
    try:
        res = run_db(lambda: sb.table("users").select("username").eq("username", "admin").limit(1).execute(),
                     what="users select (check admin)")
        if res and res.data:
            return
    except Exception:
        pass
    try:
        hashed = bcrypt.hashpw("1234".encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        run_db(lambda: sb.table("users").insert({
            "username":"admin","password_hash":hashed,"role":"admin","failed_attempts":0,"locked_until":None
        }).execute(), what="users insert (admin)")
        st.info("Standaard admin aangemaakt: admin / 1234 — wijzig dit wachtwoord in Beheer.")
    except Exception:
        st.warning("Kon admin niet automatisch aanmaken. Controleer RLS/policies op 'users'.")

# ──────────────────────────────
# UI helpers
# ──────────────────────────────
def appbar(suffix: str):
    col1, col2, col3 = st.columns([5,3,2])
    with col1:
        st.markdown("<div class='appbar-left'>ANWW Duikapp</div>", unsafe_allow_html=True)
    with col2:
        st.markdown(
            f"<div class='appbar-mid'><div class='badge'>"
            f"{st.session_state.get('username','?')} · {normalize_role(st.session_state.get('role'))}"
            f"</div></div>",
            unsafe_allow_html=True
        )
    with col3:
        if st.button("Uitloggen", key=f"logout_{suffix}"):
            st.session_state.clear()
            st.rerun()

# ──────────────────────────────
# Pagina's
# ──────────────────────────────
def login_page():
    ensure_admin_exists()

    st.markdown(f"🧩 Build: **{APP_BUILD}**", unsafe_allow_html=True)

    login_logo_url = (st.secrets.get("app", {}).get("login_logo_url", "") or "").strip()
    if login_logo_url:
        c1, c2, c3 = st.columns([1,2,1])
        with c2:
            try: st.image(login_logo_url, width=240)
            except Exception: st.title("ANWW Duikapp")
    else:
        st.title("ANWW Duikapp")

    with st.form("login_form", clear_on_submit=False):
        u = st.text_input("Gebruikersnaam", key="login_user")
        p = st.text_input("Wachtwoord", type="password", key="login_pw")
        submitted = st.form_submit_button("Login")

    if not submitted:
        return

    if not u or not p:
        st.error("Vul zowel gebruikersnaam als wachtwoord in.")
        return

    user = get_user(u)
    if not user:
        st.error("Onbekende gebruiker")
        return

    locked, until = is_locked(user)
    if locked:
        st.error(f"Account geblokkeerd tot {until} UTC.")
        return

    ok = False
    ph = (user.get("password_hash") or "").encode("utf-8")
    if ph:
        try: ok = bcrypt.checkpw(p.encode("utf-8"), ph)
        except Exception: ok = False

    if ok:
        clear_lock(u)
        st.session_state.logged_in = True
        st.session_state.username = u
        st.session_state.role = normalize_role(user.get("role"))
        st.rerun()
    else:
        attempts, locked_until = register_failed_attempt(u)
        if locked_until:
            st.error(f"Teveel foute pogingen. Geblokkeerd tot {locked_until} UTC.")
        else:
            left = MAX_ATTEMPTS - attempts
            st.error(f"Onjuist wachtwoord. Nog {left} poging(en) over.")

def page_duiken():
    role = current_role()
    if is_viewer_effective():
        st.error("Alleen-lezen gebruiker: geen toegang tot 'Duiken invoeren'.")
        return

    appbar("duiken")

    if "last_duik_date" not in st.session_state:
        st.session_state.last_duik_date = None
    if "remove_from_sel" not in st.session_state:
        st.session_state.remove_from_sel = []

    plaatsen_list = list_plaatsen()
    place_options = ["— kies —"] + plaatsen_list

    datum = st.date_input("Datum", datetime.date.today(), key="duiken_datum", format="DD/MM/YYYY")
    if st.session_state.last_duik_date is None or st.session_state.last_duik_date != datum:
        if st.session_state.last_duik_date is not None:
            st.session_state["duiken_plaats"] = place_options[0]
            st.session_state["duiken_sel_duikers"] = []
            st.session_state["duiken_duikcode"] = ""
        st.session_state.last_duik_date = datum

    duikcode = st.text_input("Duikcode (optioneel, bv. 'Ochtend', 'Duik 1')", key="duiken_duikcode")

    pending_remove = st.session_state.get("remove_from_sel", [])
    if pending_remove:
        cur_list = st.session_state.get("duiken_sel_duikers", [])
        st.session_state["duiken_sel_duikers"] = [d for d in cur_list if d not in pending_remove]
        st.session_state["remove_from_sel"] = []

    plaats = st.selectbox("Duikplaats", place_options, index=0, key="duiken_plaats")
    duikers = list_duikers()
    sel = st.multiselect("Kies duikers", duikers, key="duiken_sel_duikers")

    if role == "admin":
        with st.expander("Duikplaats/duiker toevoegen"):
            c1, c2 = st.columns(2)
            with c1:
                np = st.text_input("Nieuwe duikplaats", key="nieuwe_plaats")
                if st.button("Voeg duikplaats toe"):
                    if np and np not in plaatsen_list:
                        add_plaats(np); st.success(f"Duikplaats '{np}' toegevoegd."); st.rerun()
                    else:
                        st.warning("Leeg of al bestaand.")
            with c2:
                nd = st.text_input("Nieuwe duiker", key="nieuwe_duiker")
                if st.button("Voeg duiker toe"):
                    if nd and nd not in duikers:
                        add_duiker(nd); st.success(f"Duiker '{nd}' toegevoegd."); st.rerun()
                    else:
                        st.warning("Leeg of al bestaand.")

    st.markdown("##### Geselecteerde duikers (nog niet opgeslagen)")
    if sel:
        st.write(", ".join(sel))
        rm_sel = st.multiselect("Verwijder uit selectie", sel, key="duiken_sel_remove")
        if st.button("Verwijder gekozen uit selectie", key="btn_remove_from_sel"):
            st.session_state["remove_from_sel"] = rm_sel
            st.rerun()
    else:
        st.caption("Nog geen duikers geselecteerd.")

    can_save = (plaats != "— kies —") and (len(sel) > 0)
    if st.button("Opslaan duik(en)", type="primary",
                 disabled=(is_viewer_effective() or not can_save), key="duiken_opslaan"):
        rows = [{"datum": datum.isoformat(), "plaats": plaats, "duiker": naam, "duikcode": duikcode or ""} for naam in sel]
        save_duiken(rows)
        st.success(f"{len(sel)} duik(en) opgeslagen voor {plaats} · {duikcode or '—'} op {datum.strftime('%d/%m/%Y')}.")

    if plaats != "— kies —":
        f = fetch_duiken({"datum_eq": datum.isoformat(), "plaats_eq": plaats, "duikcode_eq": duikcode or ""})
        st.markdown("##### Bestaande inschrijvingen voor deze duik")
        if f.empty:
            st.caption("Nog geen opgeslagen inschrijvingen voor deze datum/plaats/duikcode.")
        else:
            view = f[["duiker"]].rename(columns={"duiker":"Aanwezige duiker"})
            st.dataframe(view, use_container_width=True, hide_index=True)
            if not is_viewer_effective():
                rm_saved = st.multiselect("Selecteer duikers om te verwijderen uit deze duik",
                                          f["duiker"].unique().tolist(), key="rm_saved")
                if st.button("Verwijder geselecteerde uit deze duik", key="btn_rm_saved"):
                    ids = f.loc[f["duiker"].isin(rm_saved), "id"].astype(int).tolist()
                    delete_duiken_by_ids(ids)
                    st.success(f"Verwijderd: {len(ids)} uit {plaats} · {duikcode or '—'} op {datum.strftime('%d/%m/%Y')}.")
                    st.rerun()

def page_overzicht():
    appbar("overzicht")
    df = fetch_duiken()
    if df.empty:
        st.info("Nog geen duiken geregistreerd.")
        return

    df["Datum"] = pd.to_datetime(df["datum"]).dt.date
    df["Plaats"] = df["plaats"]
    df["Duiker"] = df["duiker"]
    df["Duikcode"] = df["duikcode"].fillna("")

    unique = df.drop_duplicates(subset=["Datum","Plaats","Duikcode"]).sort_values(
        ["Datum","Plaats","Duikcode"], ascending=[False, True, True]
    )
    labels = [f"{d.strftime('%d/%m/%Y')} · {p} · {c if c else '—'}"
              for d,p,c in zip(unique["Datum"], unique["Plaats"], unique["Duikcode"])]
    keuze = st.selectbox("Specifieke duik (optioneel)", ["Alle duiken"] + labels, index=0, key="spec_duik")

    c1,c2,c3,c4 = st.columns([1,1,1,2])
    with c1:
        min_d,max_d = df["Datum"].min(), df["Datum"].max()
        rng = st.date_input("Datumrange", (min_d, max_d), format="DD/MM/YYYY")
    with c2:
        plaatsen = ["Alle"] + sorted(df["Plaats"].dropna().unique().tolist())
        pf = st.selectbox("Duikplaats", plaatsen, index=0)
    with c3:
        codes = ["Alle"] + sorted([c if c else "—" for c in df["Duikcode"].fillna('').unique().tolist()])
        cf = st.selectbox("Duikcode", codes, index=0)
    with c4:
        duikers = ["Alle"] + sorted(df["Duiker"].dropna().unique().tolist())
        dfilt = st.selectbox("Duiker", duikers, index=0)

    if keuze != "Alle duiken":
        idx = labels.index(keuze)
        t = unique.iloc[idx]
        f = df[(df["Datum"]==t["Datum"]) & (df["Plaats"]==t["Plaats"]) & (df["Duikcode"]==t["Duikcode"])].copy()
        st.markdown(f"**Aanwezigen voor {t['Plaats']} · {t['Duikcode'] or '—'} op {t['Datum'].strftime('%d/%m/%Y')}:**")
    else:
        start,end = rng if isinstance(rng, tuple) else (df["Datum"].min(), df["Datum"].max())
        f = df[(df["Datum"]>=start)&(df["Datum"]<=end)].copy()
        if pf!="Alle": f = f[f["Plaats"]==pf]
        if cf!="Alle": f = f[f["Duikcode"].replace({'':'—'})==cf]
        if dfilt!="Alle": f = f[f["Duiker"]==dfilt]

    f = f.sort_values(["Datum","Plaats","Duikcode","Duiker"])
    view = f[["Datum","Plaats","Duiker","Duikcode"]].copy()
    view["Datum"] = pd.to_datetime(view["Datum"]).dt.strftime("%d/%m/%Y")

    f_with_id = f.reset_index(drop=True).copy()
    f_with_id.insert(0, "Selecteer", False)
    f_with_id.rename(columns={"id":"RowId"}, inplace=True)

    if is_viewer_effective():
        st.dataframe(
            f_with_id[["RowId","Datum","Plaats","Duiker","Duikcode"]],
            use_container_width=True, hide_index=True
        )
    else:
        edited = st.data_editor(
            f_with_id[["Selecteer","RowId","Datum","Plaats","Duiker","Duikcode"]],
            num_rows="fixed", use_container_width=True, hide_index=True,
            column_config={"Selecteer": st.column_config.CheckboxColumn("Selecteer")}
        )
        to_delete_ids = edited.loc[edited["Selecteer"]==True, "RowId"].astype(int).tolist()
        if st.button("Verwijder geselecteerde rijen", disabled=(len(to_delete_ids)==0)):
            delete_duiken_by_ids(to_delete_ids)
            st.success(f"Verwijderd: {len(to_delete_ids)} rij(en).")
            st.rerun()

    out = io.BytesIO()
    with pd.ExcelWriter(out, engine="openpyxl") as w:
        view.to_excel(w, index=False, sheet_name="Duiken")
    st.download_button("Download Excel (huidige filter)", data=out.getvalue(),
        file_name="duiken_export.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

def page_afrekening():
    appbar("afrekening")
    df = fetch_duiken()
    if df.empty:
        st.info("Nog geen duiken geregistreerd.")
        return

    df["Datum"] = pd.to_datetime(df["datum"]).dt.date
    df["Plaats"] = df["plaats"]
    df["Duiker"] = df["duiker"]

    c1,c2,c3 = st.columns(3)
    with c1:
        min_d,max_d = df["Datum"].min(), df["Datum"].max()
        rng = st.date_input("Periode", (min_d,max_d), key="afr_range", format="DD/MM/YYYY")
    with c2:
        bedrag = st.number_input("Bedrag per duik (€)", min_value=0.0, step=1.0, value=5.0, key="afr_bedrag")
    with c3:
        pf = st.selectbox("Duikplaats (optioneel)", ["Alle"] + sorted(df["Plaats"].dropna().unique().tolist()), index=0, key="afr_plaats")

    start,end = rng if isinstance(rng, tuple) else (df["Datum"].min(), df["Datum"].max())
    m = (df["Datum"]>=start)&(df["Datum"]<=end)
    if pf!="Alle": m &= df["Plaats"]==pf
    s = df.loc[m].copy()

    if s.empty:
        st.warning("Geen duiken in de gekozen periode/filters.")
        return

    per = s.groupby("Duiker").size().reset_index(name="AantalDuiken")
    per["Bedrag"] = (per["AantalDuiken"]*bedrag).round(2)
    st.dataframe(per, use_container_width=True, hide_index=True)
    total = per["Bedrag"].sum()
    st.metric("Totaal uit te keren", f"€ {total:,.2f}".replace(",", "X").replace(".", ",").replace("X","."))

    out = io.BytesIO()
    with pd.ExcelWriter(out, engine="openpyxl") as w:
        per.to_excel(w, index=False, sheet_name="Afrekening")
        s.sort_values(["Datum","Plaats","duikcode","Duiker"]).to_excel(w, index=False, sheet_name="Detail")
    st.download_button("⬇️ Download Afrekening (Excel)", data=out.getvalue(),
        file_name="Afrekening.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

def page_beheer():
    if is_viewer_effective() or current_role() != "admin":
        st.error("Toegang geweigerd — alleen admins.")
        return

    appbar("beheer")
    tabs = st.tabs(["Gebruikers","Duikers","Duikplaatsen","Back-up & export"])

    with tabs[0]:
        res = run_db(lambda: sb.table("users").select("username, role, failed_attempts, locked_until").order("username").execute(),
                     what="users select (beheer)")
        users_df = pd.DataFrame(res.data or [])
        st.dataframe(users_df, use_container_width=True, hide_index=True)

        st.subheader("Rol van gebruiker wijzigen")
        all_usernames = users_df["username"].astype(str).tolist() if not users_df.empty else []
        sel_role_user = st.selectbox("Kies gebruiker", all_usernames, key="chg_role_user")
        new_role = st.selectbox("Nieuwe rol", ["viewer","user","admin"], index=1, key="chg_role_new")
        if st.button("Wijzig rol"):
            if not sel_role_user:
                st.warning("Kies eerst een gebruiker.")
            else:
                try:
                    current = get_user(sel_role_user)
                    cur_role = normalize_role(current.get("role") if current else "")
                    if cur_role == "admin" and new_role != "admin":
                        admins = set(list_admin_usernames()); admins.discard(sel_role_user)
                        if len(admins) == 0:
                            st.error("Er moet minstens één andere admin overblijven.")
                        else:
                            update_user_role(sel_role_user, new_role); st.success(f"Rol gewijzigd naar {new_role}."); st.rerun()
                    else:
                        update_user_role(sel_role_user, new_role); st.success(f"Rol gewijzigd naar {new_role}."); st.rerun()
                except Exception as e:
                    st.error(f"Rol wijzigen mislukt: {e}")

        st.divider()
        st.subheader("Gebruikers verwijderen")
        protect = {"admin", st.session_state.get("username","")}
        sel_del_users = st.multiselect("Kies gebruikers om te verwijderen", [u for u in all_usernames if u not in protect])
        if st.button("Verwijder geselecteerde gebruikers", disabled=(len(sel_del_users)==0)):
            remaining_admins = set(list_admin_usernames()) - set(sel_del_users)
            if len(remaining_admins) == 0:
                st.error("Minstens één admin moet overblijven.")
            else:
                ok, n, err = delete_users(sel_del_users)
                if ok: st.success(f"Verwijderd: {n} gebruiker(s)."); st.rerun()
                else:  st.error(f"Verwijderen mislukt: {err}")

        st.divider()
        st.subheader("Nieuwe gebruiker")
        c1,c2,c3 = st.columns(3)
        with c1: u = st.text_input("Username")
        with c2: p = st.text_input("Wachtwoord")
        with c3: r = st.selectbox("Rol", ["viewer","user","admin"], index=0)
        if st.button("Gebruiker toevoegen"):
            if u and p and (get_user(u) is None):
                hashed = bcrypt.hashpw(p.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
                try:
                    run_db(lambda: sb.table("users").insert({
                        "username":u,"password_hash":hashed,"role":normalize_role(r),
                        "failed_attempts":0,"locked_until":None
                    }).execute(), what="users insert (beheer)")
                    st.success(f"Gebruiker '{u}' toegevoegd ({r})."); st.rerun()
                except Exception as e:
                    st.error(f"Toevoegen mislukt: {e}")
            else:
                st.warning("Ongeldig of reeds bestaand.")

        st.divider()
        st.subheader("Wachtwoord resetten / Deblokkeren")
        res = run_db(lambda: sb.table("users").select("username").order("username").execute(), what="users select (pw)")
        all_users_pw = [row["username"] for row in (res.data or [])]
        sel_user = st.selectbox("Kies gebruiker", all_users_pw)
        new_pw = st.text_input("Nieuw wachtwoord")
        colr1, colr2 = st.columns(2)
        with colr1:
            if st.button("Reset wachtwoord"):
                if sel_user and new_pw:
                    try: set_password(sel_user, new_pw); st.success(f"Wachtwoord van '{sel_user}' is gewijzigd.")
                    except Exception as e: st.error(f"Reset mislukt: {e}")
                else:
                    st.warning("Selecteer gebruiker en geef nieuw wachtwoord in.")
        with colr2:
            if st.button("Deblokkeer account"):
                try: clear_lock(sel_user); st.success(f"Account van '{sel_user}' is gedeblokkeerd.")
                except Exception as e: st.error(f"Deblokkeren mislukt: {e}")

    with tabs[1]:
        duikers = list_duikers()
        st.dataframe(pd.DataFrame({"Naam": duikers}), use_container_width=True, hide_index=True)

        st.subheader("Duikers verwijderen")
        sel_duikers = st.multiselect("Kies duikers om te verwijderen", duikers)
        if st.button("Verwijder geselecteerde duikers", disabled=(len(sel_duikers)==0)):
            ok, n, err = delete_duikers(sel_duikers)
            if ok: st.success(f"Verwijderd: {n} duiker(s)."); st.rerun()
            else:  st.error(f"Verwijderen mislukt: {err}")

        st.divider()
        nd = st.text_input("Nieuwe duiker naam")
        if st.button("Toevoegen aan duikers"):
            if nd and (nd not in duikers):
                try: add_duiker(nd); st.success(f"Duiker '{nd}' toegevoegd."); st.rerun()
                except Exception as e: st.error(f"Toevoegen mislukt: {e}")
            else:
                st.warning("Leeg of al bestaand.")

    with tabs[2]:
        plaatsen = list_plaatsen()
        st.dataframe(pd.DataFrame({"Plaats": plaatsen}), use_container_width=True, hide_index=True)

        st.subheader("Duikplaatsen verwijderen")
        sel_plaatsen = st.multiselect("Kies duikplaatsen om te verwijderen", plaatsen)
        if st.button("Verwijder geselecteerde duikplaatsen", disabled=(len(sel_plaatsen)==0)):
            ok, n, err = delete_plaatsen(sel_plaatsen)
            if ok: st.success(f"Verwijderd: {n} duikplaats(en)."); st.rerun()
            else:  st.error(f"Verwijderen mislukt: {err}")

        st.divider()
        np = st.text_input("Nieuwe duikplaats")
        if st.button("Toevoegen aan duikplaatsen"):
            if np and (np not in plaatsen):
                try: add_plaats(np); st.success(f"Duikplaats '{np}' toegevoegd."); st.rerun()
                except Exception as e: st.error(f"Toevoegen mislukt: {e}")
            else:
                st.warning("Leeg of al bestaand.")

    with tabs[3]:
        st.info("Alle data wordt automatisch opgeslagen in Supabase. "
                "Hier kun je een back-up (Excel) downloaden van alle tabellen.")
        if st.button("Maak back-up (Excel)"):
            out = io.BytesIO()
            users = run_db(lambda: sb.table("users").select("*").execute(), what="users select (backup)")
            duikers = run_db(lambda: sb.table("duikers").select("*").execute(), what="duikers select (backup)")
            plaatsen = run_db(lambda: sb.table("duikplaatsen").select("*").execute(), what="duikplaatsen select (backup)")
            duiken = run_db(lambda: sb.table("duiken").select("*").execute(), what="duiken select (backup)")
            df_users = pd.DataFrame(users.data or [])
            df_duikers = pd.DataFrame(duikers.data or [])
            df_plaatsen = pd.DataFrame(plaatsen.data or [])
            df_duiken = pd.DataFrame(duiken.data or [])
            stamp = dt.utcnow().strftime("%Y%m%d_%H%M%S")
            with pd.ExcelWriter(out, engine="openpyxl") as w:
                df_users.to_excel(w, index=False, sheet_name="users")
                df_duikers.to_excel(w, index=False, sheet_name="duikers")
                df_plaatsen.to_excel(w, index=False, sheet_name="duikplaatsen")
                df_duiken.to_excel(w, index=False, sheet_name="duiken")
            st.download_button(
                "⬇️ Download back-up",
                data=out.getvalue(),
                file_name=f"anww_backup_{stamp}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )

# ──────────────────────────────
# Main
# ──────────────────────────────
def main():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        login_page()
        return

    # Live rol refresh
    try:
        urow = get_user(st.session_state.get("username", ""))
        if urow:
            st.session_state.role = normalize_role(urow.get("role"))
    except Exception:
        pass

    role = current_role()

    st.markdown(
        f"<div class='badge'>Ingelogd als: <b>{st.session_state.get('username','?')}</b> · Rol: <b>{role}</b>"
        + (" · READ-ONLY (noodslot)" if FORCE_READONLY else "")
        + "</div>",
        unsafe_allow_html=True
    )

    if role == "admin" and not FORCE_READONLY:
        tabs = st.tabs(["Duiken invoeren", "Overzicht", "Afrekening", "Beheer"])
        with tabs[0]: page_duiken()
        with tabs[1]: page_overzicht()
        with tabs[2]: page_afrekening()
        with tabs[3]: page_beheer()
    elif role == "user" and not FORCE_READONLY:
        tabs = st.tabs(["Duiken invoeren", "Overzicht", "Afrekening"])
        with tabs[0]: page_duiken()
        with tabs[1]: page_overzicht()
        with tabs[2]: page_afrekening()
    else:
        tabs = st.tabs(["Overzicht", "Afrekening"])
        with tabs[0]: page_overzicht()
        with tabs[1]: page_afrekening()

if __name__ == "__main__":
    main()
