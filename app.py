# app.py — ANWW Duikapp (voornaam/achternaam + afrekening met blokken & instelbaar restsaldo)
# Gebaseerd op je aangeleverde app; alleen wijzigingen toegevoegd die je vroeg.

import streamlit as st
from datetime import datetime as dt
import datetime
import pandas as pd
import bcrypt
import io
import time
import math

from supabase import create_client, Client
from postgrest.exceptions import APIError
import httpx  # voor ConnectError/ReadTimeout

APP_BUILD = "v2025-09-30-ANWW-04+splitname-blocks-restsaldo"

# ──────────────────────────────
# Basisconfig & thema
# ──────────────────────────────
st.set_page_config(page_title="ANWW Duikapp", layout="wide")

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

    try:
        client = create_client(url, key)
    except Exception as e:
        st.error(f"Kon Supabase client niet maken: {e}")
        st.stop()

    # mini probe
    try:
        client.table("users").select("username").limit(1).execute()
    except Exception:
        pass
    return client

sb = get_client()

# Retry wrapper

def run_db(fn, *, tries=3, backoff=0.6, what="database call"):
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
            st.error(
                f"API-fout bij {what}. Controleer tabel/policy/RLS voor anon key."
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
# Rollen / security
# ──────────────────────────────
MAX_ATTEMPTS = 5
LOCK_MINUTES = 15
ALLOWED_ROLES = {"admin", "user", "viewer"}
FORCE_READONLY = bool(st.secrets.get("app", {}).get("force_readonly", False))


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
# Helpers naam-splitting
# ──────────────────────────────

def _fullname(vn: str | None, an: str | None) -> str:
    vn = (vn or "").strip(); an = (an or "").strip()
    return (vn + (" " if vn and an else "") + an).strip()


def _split_guess(full: str) -> tuple[str,str]:
    s = (full or "").strip()
    if not s: return "",""
    parts = s.split()
    if len(parts)==1: return "", parts[0]
    return parts[0], " ".join(parts[1:])

# ──────────────────────────────
# DB helpers (users/duikers/plaatsen/duiken/afrekeningen)
# ──────────────────────────────

def get_user(username: str):
    res = run_db(lambda: sb.table("users").select("*").eq("username", username).limit(1).execute(),
                 what="users select")
    rows = res.data or []
    return rows[0] if rows else None


def list_admin_usernames() -> list[str]:
    res = run_db(lambda: sb.table("users").select("username, role").eq("role","admin").execute(), what="users (admins)")
    return [r["username"] for r in (res.data or [])]


def set_password(username: str, new_password: str):
    _ensure_not_viewer()
    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    run_db(lambda: sb.table("users").update({"password_hash": hashed, "failed_attempts": 0, "locked_until": None})
           .eq("username", username).execute(), what="users update (password)")


def update_user_role(username: str, new_role: str):
    _ensure_not_viewer()
    run_db(lambda: sb.table("users").update({"role": normalize_role(new_role)}).eq("username", username).execute(),
           what="users update (role)")


def clear_lock(username: str):
    _ensure_not_viewer()
    run_db(lambda: sb.table("users").update({"failed_attempts": 0, "locked_until": None}).eq("username", username).execute(),
           what="users update (unlock)")

# ——— DU I K E R S ———

def list_duikers_weergave() -> list[str]:
    """Retourneert combinaties 'Achternaam, Voornaam' indien beschikbaar, anders legacy 'naam'. Gesorteerd op achternaam."""
    try:
        res = run_db(lambda: sb.table("duikers").select("voornaam, achternaam, naam, rest_saldo").execute(), what="duikers select (split)")
        rows = res.data or []
        out = []
        for r in rows:
            vn, an = r.get("voornaam"), r.get("achternaam")
            if (vn is not None) or (an is not None):
                label = f"{(an or '').strip()}, {(vn or '').strip()}".strip(', ')
                out.append(label)
            else:
                out.append((r.get("naam") or "").strip())
        def sort_key(x:str):
            if "," in x:
                an, vn = [p.strip() for p in x.split(",",1)]
                return (an.lower(), vn.lower())
            vn, an = _split_guess(x)
            return (an.lower(), vn.lower())
        return sorted([o for o in out if o], key=sort_key)
    except Exception:
        res = run_db(lambda: sb.table("duikers").select("naam").order("naam").execute(), what="duikers select (legacy)")
        return [r["naam"] for r in (res.data or [])]


def add_duiker_legacy(name: str):
    _ensure_not_viewer()
    run_db(lambda: sb.table("duikers").insert({"naam": name}).execute(), what="duikers insert (legacy)")


def add_duiker_split(vn: str, an: str, rest: float = 0.0):
    _ensure_not_viewer()
    payload = {"voornaam": (vn or '').strip(), "achternaam": (an or '').strip(), "naam": _fullname(vn, an), "rest_saldo": float(rest)}
    run_db(lambda: sb.table("duikers").insert(payload).execute(), what="duikers insert (split)")


def update_duiker_rest(vn: str, an: str, rest: float):
    _ensure_not_viewer()
    run_db(lambda: sb.table("duikers").update({"rest_saldo": float(rest)})
           .eq("voornaam", (vn or '').strip()).eq("achternaam", (an or '').strip()).execute(),
           what="duikers update rest")


def delete_duikers(names_or_labels: list[str]) -> tuple[bool, int, str | None]:
    if not names_or_labels: return True, 0, None
    try:
        _ensure_not_viewer()
        deleted = 0
        for disp in names_or_labels:
            if "," in disp:
                an, vn = [p.strip() for p in disp.split(",",1)]
                run_db(lambda: sb.table("duikers").delete().eq("voornaam", vn).eq("achternaam", an).execute(), what="duikers delete (split)")
                deleted += 1
            else:
                run_db(lambda: sb.table("duikers").delete().eq("naam", disp).execute(), what="duikers delete (legacy)")
                deleted += 1
        return True, deleted, None
    except Exception as e:
        return False, 0, str(e)

# ——— P L A A T S E N ———

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

# ——— D U I K E N ———

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

# ——— A F R E K E N I N G E N ———

def get_rest_saldo(vn: str, an: str) -> float:
    res = run_db(lambda: sb.table("duikers").select("rest_saldo").eq("voornaam", (vn or '').strip()).eq("achternaam", (an or '').strip()).limit(1).execute(),
                 what="duikers rest_saldo")
    rows = res.data or []
    return float((rows[0] or {}).get("rest_saldo", 0)) if rows else 0.0


def set_rest_saldo(vn: str, an: str, value: float):
    update_duiker_rest(vn, an, value)


def insert_afrekening(row: dict):
    run_db(lambda: sb.table("afrekeningen").insert(row).execute(), what="afrekeningen insert")

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
    st.title("ANWW Duikapp")
    with st.form("login_form", clear_on_submit=False):
        u = st.text_input("Gebruikersnaam", key="login_user")
        p = st.text_input("Wachtwoord", type="password", key="login_pw")
        submitted = st.form_submit_button("Login")
    if not submitted: return

    if not u or not p:
        st.error("Vul zowel gebruikersnaam als wachtwoord in."); return

    user = get_user(u)
    if not user:
        st.error("Onbekende gebruiker"); return

    ph = (user.get("password_hash") or "").encode("utf-8")
    ok = bcrypt.checkpw(p.encode("utf-8"), ph) if ph else False
    if ok:
        st.session_state.logged_in = True
        st.session_state.username = u
        st.session_state.role = normalize_role(user.get("role"))
        st.rerun()
    else:
        st.error("Onjuist wachtwoord.")


def page_duiken():
    role = current_role()
    if is_viewer_effective():
        st.error("Alleen-lezen gebruiker: geen toegang tot 'Duiken invoeren'."); return
    appbar("duiken")

    plaatsen_list = list_plaatsen()
    place_options = ["— kies —"] + plaatsen_list

    datum = st.date_input("Datum", datetime.date.today(), key="duiken_datum", format="DD/MM/YYYY")
    duikcode = st.text_input("Duikcode (optioneel, bv. 'Ochtend', 'Duik 1')", key="duiken_duikcode")
    plaats = st.selectbox("Duikplaats", place_options, index=0, key="duiken_plaats")

    # Duiker-selectie
    labels = list_duikers_weergave()  # Achternaam, Voornaam
    sel = st.multiselect("Kies duikers", labels, key="duiken_sel_duikers")

    if role == "admin":
        with st.expander("➕ Duiker toevoegen (Voornaam/Achternaam)"):
            c1, c2, c3 = st.columns([1,1,1])
            with c1: vn = st.text_input("Voornaam", key="new_vn")
            with c2: an = st.text_input("Achternaam", key="new_an")
            with c3: rest0 = st.number_input("Start rest (€)", min_value=0.0, step=0.5, value=0.0, key="new_rest")
            if st.button("Toevoegen", key="btn_add_duiker_split"):
                if vn or an:
                    try:
                        add_duiker_split(vn, an, rest0); st.success(f"Toegevoegd: {_fullname(vn, an)}"); st.rerun()
                    except Exception as e: st.error(f"Toevoegen mislukt: {e}")
                else:
                    st.warning("Geef minstens voornaam of achternaam.")

    st.markdown("##### Geselecteerde duikers (nog niet opgeslagen)")
    if sel:
        st.write(", ".join(sel))
    else:
        st.caption("Nog geen duikers geselecteerd.")

    can_save = (plaats != "— kies —") and (len(sel) > 0)
    if st.button("Opslaan duik(en)", type="primary", disabled=(is_viewer_effective() or not can_save), key="duiken_opslaan"):
        # Sla nog steeds de displaynaam op in 'duiken.duiker' (compatibel met je huidige structuur)
        rows = [{"datum": datum.isoformat(), "plaats": plaats, "duiker": lab.replace(", ", " "), "duikcode": duikcode or ""} for lab in sel]
        save_duiken(rows)
        st.success(f"{len(sel)} duik(en) opgeslagen voor {plaats} · {duikcode or '—'} op {datum.strftime('%d/%m/%Y')}.")


def page_overzicht():
    appbar("overzicht")
    df = fetch_duiken()
    if df.empty:
        st.info("Nog geen duiken geregistreerd."); return

    df["Datum"] = pd.to_datetime(df["datum"]).dt.date
    df["Plaats"] = df["plaats"]
    df["Duiker"] = df["duiker"]
    df["Duikcode"] = df["duikcode"].fillna("")

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

    start,end = rng if isinstance(rng, tuple) else (df["Datum"].min(), df["Datum"].max())
    f = df[(df["Datum"]>=start)&(df["Datum"]<=end)].copy()
    if pf!="Alle": f = f[f["Plaats"]==pf]
    if cf!="Alle": f = f[f["Duikcode"].replace({'':'—'})==cf]
    if dfilt!="Alle": f = f[f["Duiker"]==dfilt]

    f = f.sort_values(["Datum","Plaats","Duikcode","Duiker"])
    view = f[["Datum","Plaats","Duiker","Duikcode"]].copy()
    view["Datum"] = pd.to_datetime(view["Datum"]).dt.strftime("%d/%m/%Y")

    st.dataframe(view, use_container_width=True, hide_index=True)

    out = io.BytesIO()
    with pd.ExcelWriter(out, engine="openpyxl") as w:
        view.to_excel(w, index=False, sheet_name="Duiken")
    st.download_button("Download Excel (huidige filter)", data=out.getvalue(), file_name="duiken_export.xlsx",
                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


def page_afrekening():
    appbar("afrekening")
    df = fetch_duiken()
    if df.empty:
        st.info("Nog geen duiken geregistreerd."); return

    df["Datum"] = pd.to_datetime(df["datum"]).dt.date
    df["Plaats"] = df["plaats"]
    df["Duiker"] = df["duiker"]

    c1,c2,c3,c4 = st.columns(4)
    with c1:
        min_d,max_d = df["Datum"].min(), df["Datum"].max()
        rng = st.date_input("Periode", (min_d,max_d), key="afr_range", format="DD/MM/YYYY")
    with c2:
        bedrag = st.number_input("Bedrag per duik (€)", min_value=0.0, step=0.5, value=5.0, key="afr_bedrag")
    with c3:
        pf = st.selectbox("Duikplaats (optioneel)", ["Alle"] + sorted(df["Plaats"].dropna().unique().tolist()), index=0, key="afr_plaats")
    with c4:
        blokgrootte = st.number_input("Blokgrootte (€)", min_value=0.0, step=10.0, value=30.0, key="afr_blok")

    start,end = rng if isinstance(rng, tuple) else (df["Datum"].min(), df["Datum"].max())
    m = (df["Datum"]>=start)&(df["Datum"]<=end)
    if pf!="Alle": m &= df["Plaats"]==pf
    s = df.loc[m].copy()
    if s.empty:
        st.warning("Geen duiken in de gekozen periode/filters."); return

    # Per duiker tellen
    per = s.groupby("Duiker").size().reset_index(name="AantalDuiken")
    per["Bruto"] = (per["AantalDuiken"]*bedrag).round(2)

    # Koppel naar (Voornaam, Achternaam) en Rest (via duikers)
    # We zoeken eerst exacte match op 'naam'; anders proberen we te raden
    ddf = run_db(lambda: sb.table("duikers").select("voornaam, achternaam, naam, rest_saldo").execute(), what="duikers join").data or []
    ddf = pd.DataFrame(ddf)

    vns, ans, rests = [], [], []
    for disp in per["Duiker"].astype(str).tolist():
        vn, an, rest = "", "", 0.0
        if not ddf.empty:
            row = ddf.loc[ddf["naam"]==disp]
            if not row.empty:
                vn = (row.iloc[0].get("voornaam") or "").strip()
                an = (row.iloc[0].get("achternaam") or "").strip()
                rest = float(row.iloc[0].get("rest_saldo") or 0)
            else:
                vn, an = _split_guess(disp)
                # probeer lookup op gesplitste velden
                row2 = ddf.loc[(ddf["voornaam"].fillna("").str.strip()==vn) & (ddf["achternaam"].fillna("").str.strip()==an)]
                if not row2.empty: rest = float(row2.iloc[0].get("rest_saldo") or 0)
        else:
            vn, an = _split_guess(disp)
        vns.append(vn); ans.append(an); rests.append(round(float(rest),2))

    per["Voornaam"] = vns
    per["Achternaam"] = ans
    per["RestOud"] = rests
    per["Totaal"] = (per["Bruto"] + per["RestOud"]).round(2)

    # Blokken
    def calc_blokken(total: float) -> tuple[int,float,float]:
        if blokgrootte <= 0:
            return 0, 0.0, round(total,2)
        n = math.floor(total / blokgrootte)
        uit = round(n * blokgrootte, 2)
        rest = round(total - uit, 2)
        return n, uit, rest

    rows = []
    for _, r in per.iterrows():
        n, uit, rest = calc_blokken(float(r["Totaal"]))
        rows.append({**r.to_dict(), "Blokken": n, "UitTeBetalen": uit, "RestNieuw": rest})
    per = pd.DataFrame(rows)

    # Sorteer op achternaam, voornaam
    per = per.sort_values(["Achternaam","Voornaam","Duiker"], na_position="last").reset_index(drop=True)

    st.subheader("Afrekening per duiker")
    show_cols = ["Achternaam","Voornaam","AantalDuiken","Bruto","RestOud","Totaal","Blokken","UitTeBetalen","RestNieuw"]
    st.dataframe(per[show_cols], use_container_width=True, hide_index=True)

    cX,cY,cZ = st.columns(3)
    with cX:
        st.metric("Totaal uit te betalen", f"€ {float(per['UitTeBetalen'].sum()):,.2f}".replace(",","X").replace(".",",").replace("X","."))
    with cY:
        st.metric("Nieuw totaal restbedrag", f"€ {float(per['RestNieuw'].sum()):,.2f}".replace(",","X").replace(".",",").replace("X","."))
    with cZ:
        st.caption(f"Periode: {start.strftime('%d/%m/%Y')} – {end.strftime('%d/%m/%Y')} · Blok: €{blokgrootte:.2f}")

    st.divider()
    st.subheader("Historiek vastleggen / Markeer als betaald")
    st.caption("Selecteer duikers die je nu uitbetaalt. Restsaldo wordt automatisch bijgewerkt en bewaard voor volgende periode.")

    per["select"] = False
    for i in range(len(per)):
        label = f"{per.at[i,'Achternaam']}, {per.at[i,'Voornaam']}"
        per.at[i, "select"] = st.checkbox(label, key=f"sel_pay_{i}")

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
                        "blokgrootte": float(blokgrootte),
                        "aantal_duiken": int(r["AantalDuiken"]),
                        "bruto_bedrag": float(r["Bruto"]),
                        "rest_oud": float(r["RestOud"]),
                        "blokken": int(r["Blokken"]),
                        "uit_te_betalen": float(r["UitTeBetalen"]),
                        "rest_nieuw": float(r["RestNieuw"]),
                        "betaald_op": dt.utcnow().isoformat()
                    }
                    insert_afrekening(row)
                    # Update het restsaldo in duikers
                    if row["voornaam"] or row["achternaam"]:
                        set_rest_saldo(row["voornaam"], row["achternaam"], row["rest_nieuw"]) 
                st.success(f"Afrekening geregistreerd voor {len(sel)} duiker(s).")
                st.rerun()
        except Exception as e:
            st.error(f"Registratie mislukt: {e}")

    st.divider()
    st.subheader("Export (Excel)")
    out = io.BytesIO()
    with pd.ExcelWriter(out, engine="openpyxl") as w:
        per[show_cols].to_excel(w, index=False, sheet_name="Afrekening")
        s.sort_values(["Datum","Plaats","duikcode","Duiker"]).to_excel(w, index=False, sheet_name="Detail")
    st.download_button("⬇️ Download Afrekening (Excel)", data=out.getvalue(), file_name="Afrekening.xlsx",
                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


def page_beheer():
    if is_viewer_effective() or current_role() != "admin":
        st.error("Toegang geweigerd — alleen admins.")
        return

    appbar("beheer")
    tabs = st.tabs(["Gebruikers", "Duikers", "Duikplaatsen", "Back-up & export"])

    # ───────────── TAB 0: Gebruikers ─────────────
    with tabs[0]:
        res = run_db(
            lambda: sb.table("users")
                      .select("username, role, failed_attempts, locked_until")
                      .order("username").execute(),
            what="users select (beheer)"
        )
        users_df = pd.DataFrame(res.data or [])
        st.dataframe(users_df, use_container_width=True, hide_index=True)

        st.subheader("Rol van gebruiker wijzigen")
        all_usernames = users_df["username"].astype(str).tolist() if not users_df.empty else []
        sel_role_user = st.selectbox("Kies gebruiker", all_usernames, key="chg_role_user")
        new_role = st.selectbox("Nieuwe rol", ["viewer", "user", "admin"], index=1, key="chg_role_new")
        if st.button("Wijzig rol"):
            if not sel_role_user:
                st.warning("Kies eerst een gebruiker.")
            else:
                try:
                    current = get_user(sel_role_user)
                    cur_role = normalize_role(current.get("role") if current else "")
                    if cur_role == "admin" and new_role != "admin":
                        admins = set(list_admin_usernames())
                        admins.discard(sel_role_user)
                        if len(admins) == 0:
                            st.error("Er moet minstens één andere admin overblijven.")
                        else:
                            update_user_role(sel_role_user, new_role)
                            st.success(f"Rol gewijzigd naar {new_role}.")
                            st.rerun()
                    else:
                        update_user_role(sel_role_user, new_role)
                        st.success(f"Rol gewijzigd naar {new_role}.")
                        st.rerun()
                except Exception as e:
                    st.error(f"Rol wijzigen mislukt: {e}")

        st.divider()
        st.subheader("Gebruikers verwijderen")
        protect = {"admin", st.session_state.get("username", "")}
        sel_del_users = st.multiselect(
            "Kies gebruikers om te verwijderen",
            [u for u in all_usernames if u not in protect]
        )
        if st.button("Verwijder geselecteerde gebruikers", disabled=(len(sel_del_users) == 0)):
            remaining_admins = set(list_admin_usernames()) - set(sel_del_users)
            if len(remaining_admins) == 0:
                st.error("Minstens één admin moet overblijven.")
            else:
                ok, n, err = delete_users(sel_del_users)
                if ok:
                    st.success(f"Verwijderd: {n} gebruiker(s).")
                    st.rerun()
                else:
                    st.error(f"Verwijderen mislukt: {err}")

        st.divider()
        st.subheader("Nieuwe gebruiker")
        c1, c2, c3 = st.columns(3)
        with c1:
            u = st.text_input("Username")
        with c2:
            p = st.text_input("Wachtwoord")
        with c3:
            r = st.selectbox("Rol", ["viewer", "user", "admin"], index=0)
        if st.button("Gebruiker toevoegen"):
            if u and p and (get_user(u) is None):
                hashed = bcrypt.hashpw(p.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
                try:
                    run_db(
                        lambda: sb.table("users").insert({
                            "username": u,
                            "password_hash": hashed,
                            "role": normalize_role(r),
                            "failed_attempts": 0,
                            "locked_until": None
                        }).execute(),
                        what="users insert (beheer)"
                    )
                    st.success(f"Gebruiker '{u}' toegevoegd ({r}).")
                    st.rerun()
                except Exception as e:
                    st.error(f"Toevoegen mislukt: {e}")
            else:
                st.warning("Ongeldig of reeds bestaand.")

        st.divider()
        st.subheader("Wachtwoord resetten / Deblokkeren")
        res = run_db(lambda: sb.table("users").select("username").order("username").execute(),
                     what="users select (pw)")
        all_users_pw = [row["username"] for row in (res.data or [])]
        sel_user = st.selectbox("Kies gebruiker", all_users_pw)
        new_pw = st.text_input("Nieuw wachtwoord")
        colr1, colr2 = st.columns(2)
        with colr1:
            if st.button("Reset wachtwoord"):
                if sel_user and new_pw:
                    try:
                        set_password(sel_user, new_pw)
                        st.success(f"Wachtwoord van '{sel_user}' is gewijzigd.")
                    except Exception as e:
                        st.error(f"Reset mislukt: {e}")
                else:
                    st.warning("Selecteer gebruiker en geef nieuw wachtwoord in.")
        with colr2:
            if st.button("Deblokkeer account"):
                try:
                    clear_lock(sel_user)
                    st.success(f"Account van '{sel_user}' is gedeblokkeerd.")
                except Exception as e:
                    st.error(f"Deblokkeren mislukt: {e}")

    # ───────────── TAB 1: Duikers ─────────────
    with tabs[1]:
        res = run_db(
            lambda: sb.table("duikers").select("voornaam, achternaam, naam, rest_saldo").execute(),
            what="duikers select (beheer)"
        )
        ddf = pd.DataFrame(res.data or [])

        if not ddf.empty:
            # ✅ Robuuste sortering
            if {"achternaam", "voornaam"}.issubset(ddf.columns):
                ddf["_an"] = ddf["achternaam"].fillna("").str.lower()
                ddf["_vn"] = ddf["voornaam"].fillna("").str.lower()
                ddf = ddf.sort_values(["_an", "_vn"]).drop(columns=["_an", "_vn"])
            elif "naam" in ddf.columns:
                tmp = ddf["naam"].fillna("").map(_split_guess)
                ddf["_vn"] = tmp.map(lambda t: t[0])
                ddf["_an"] = tmp.map(lambda t: t[1])
                ddf = ddf.sort_values(["_an", "_vn"]).drop(columns=["_an", "_vn"])

            view = ddf.rename(columns={
                "voornaam": "Voornaam",
                "achternaam": "Achternaam",
                "rest_saldo": "Rest (start)"
            })
        else:
            view = pd.DataFrame(columns=["Voornaam", "Achternaam", "Rest (start)"])

        st.subheader("Duikers (overzicht)")
        st.dataframe(view, use_container_width=True, hide_index=True)

        st.subheader("Duikers verwijderen")
        sel_duikers = st.multiselect(
            "Kies duikers om te verwijderen",
            view["Achternaam"] + ", " + view["Voornaam"] if not view.empty else []
        )
        if st.button("Verwijder geselecteerde duikers", disabled=(len(sel_duikers) == 0)):
            ok, n, err = delete_duikers(sel_duikers)
            if ok:
                st.success(f"Verwijderd: {n} duiker(s).")
                st.rerun()
            else:
                st.error(f"Verwijderen mislukt: {err}")

        st.divider()
        st.subheader("Nieuwe duiker")
        c1, c2, c3 = st.columns([1, 1, 1])
        with c1:
            vn = st.text_input("Voornaam")
        with c2:
            an = st.text_input("Achternaam")
        with c3:
            rs = st.number_input("Start rest (€)", value=0.0, step=1.0)
        if st.button("Toevoegen aan duikers"):
            if (vn or an):
                try:
                    run_db(
                        lambda: sb.table("duikers").insert({
                            "voornaam": vn,
                            "achternaam": an,
                            "naam": f"{vn} {an}".strip(),
                            "rest_saldo": rs
                        }).execute(),
                        what="duikers insert (beheer)"
                    )
                    st.success(f"Duiker '{an}, {vn}' toegevoegd.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Toevoegen mislukt: {e}")
            else:
                st.warning("Geef minstens een voornaam of achternaam in.")

    # ───────────── TAB 2: Duikplaatsen ─────────────
    with tabs[2]:
        plaatsen = list_plaatsen()
        st.dataframe(pd.DataFrame({"Plaats": plaatsen}), use_container_width=True, hide_index=True)

        st.subheader("Duikplaatsen verwijderen")
        sel_plaatsen = st.multiselect("Kies duikplaatsen om te verwijderen", plaatsen)
        if st.button("Verwijder geselecteerde duikplaatsen", disabled=(len(sel_plaatsen) == 0)):
            ok, n, err = delete_plaatsen(sel_plaatsen)
            if ok:
                st.success(f"Verwijderd: {n} duikplaats(en).")
                st.rerun()
            else:
                st.error(f"Verwijderen mislukt: {err}")

        st.divider()
        np = st.text_input("Nieuwe duikplaats")
        if st.button("Toevoegen aan duikplaatsen"):
            if np and (np not in plaatsen):
                try:
                    add_plaats(np)
                    st.success(f"Duikplaats '{np}' toegevoegd.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Toevoegen mislukt: {e}")
            else:
                st.warning("Leeg of al bestaand.")

    # ───────────── TAB 3: Back-up & export ─────────────
    with tabs[3]:
        st.info("Alle data wordt automatisch opgeslagen in Supabase. "
                "Hier kun je een back-up (Excel) downloaden van alle tabellen.")
        if st.button("Maak back-up (Excel)"):
            out = io.BytesIO()
            users = run_db(lambda: sb.table("users").select("*").execute(),
                           what="users select (backup)")
            duikers = run_db(lambda: sb.table("duikers").select("*").execute(),
                             what="duikers select (backup)")
            plaatsen = run_db(lambda: sb.table("duikplaatsen").select("*").execute(),
                              what="duikplaatsen select (backup)")
            duiken = run_db(lambda: sb.table("duiken").select("*").execute(),
                            what="duiken select (backup)")
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
        login_page(); return

    # Rol up-to-date houden
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
