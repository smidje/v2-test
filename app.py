# app.py — ANWW Duikapp (Ledenbeheer + rol-sync + brevet -> duikers)
APP_BUILD = "v2025-10-03-ANWW-LEDENBEHEER-01"

import streamlit as st
from datetime import datetime as dt
import datetime
import pandas as pd
import io
import time
import math

from supabase import create_client, Client
from postgrest.exceptions import APIError
import httpx

st.set_page_config(page_title="ANWW Duikapp", layout="wide")

# ────────────────────────────── Thema
THEME_DEFAULTS = {
    "bg": "#f7f9fc","surface": "#f0f4ff","card": "#ffffff","border": "#e5e7eb",
    "text": "#0f172a","muted": "#475569","primary": "#2563eb","primary_contrast": "#ffffff",
    "accent": "#38bdf8","success": "#16a34a","warning": "#f59e0b","error": "#ef4444",
}
def _merge_theme(d,o): 
    if not o: return d
    x = d.copy()
    for k,v in o.items():
        if isinstance(v,str) and v.strip(): x[k]=v.strip()
    return x
def inject_theme():
    t = _merge_theme(THEME_DEFAULTS, st.secrets.get("theme"))
    css = f"""
    :root {{
      --bg:{t['bg']}; --surface:{t['surface']}; --card:{t['card']}; --border:{t['border']};
      --text:{t['text']}; --muted:{t['muted']};
      --primary:{t['primary']}; --primary-contrast:{t['primary_contrast']};
      --accent:{t['accent']}; --success:{t['success']}; --warning:{t['warning']}; --error:{t['error']};
    }}
    .stApp{{ background: radial-gradient(1200px 800px at 20% 10%, var(--surface), var(--bg) 60%); color: var(--text); }}
    .stButton > button{{ background:var(--primary)!important; color:var(--primary-contrast)!important; border:1px solid var(--primary)!important; border-radius:10px!important; box-shadow:0 4px 14px rgba(0,0,0,.08)!important; }}
    .stTabs [role="tab"][aria-selected="true"]{{ border-bottom:2px solid var(--accent); }}
    .badge{{ border:1px solid var(--border); padding:4px 10px; border-radius:999px; font-size:.9rem; background:var(--card); }}
    """
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)
inject_theme()

# ────────────────────────────── Supabase clients
@st.cache_resource
def get_anon_client() -> Client:
    import os
    supa = st.secrets.get("supabase", {})
    url = supa.get("url") or os.getenv("SUPABASE_URL")
    key = supa.get("anon_key") or os.getenv("SUPABASE_ANON_KEY")
    if not url or not key:
        st.error("Supabase configuratie ontbreekt: zet `supabase.url` en `supabase.anon_key` in secrets of env vars.")
        st.stop()
    return create_client(url, key)
sb_anon = get_anon_client()

def get_authed_client() -> Client | None:
    sess = st.session_state.get("sb_session")
    if not sess: return None
    c = get_anon_client()
    c.postgrest.auth(sess["access_token"])
    return c

def run_db(fn, *, tries=2, backoff=0.5, what="db"):
    for i in range(1, tries+1):
        try:
            client = get_authed_client() or sb_anon
            return fn(client)
        except (httpx.ConnectError, httpx.ReadTimeout) as e:
            if i < tries: time.sleep(backoff*i); continue
            st.error(f"Netwerkfout bij {what}: {e}"); st.stop()
        except APIError as e:
            st.error(f"API-fout bij {what}. Controleer tabel/policy/RLS voor je rol."); st.caption(str(e)); st.stop()
        except Exception as e:
            if i < tries: time.sleep(backoff*i); continue
            st.error(f"Onverwachte fout bij {what}: {e}"); st.stop()

# ────────────────────────────── Rollen/session
def current_role() -> str:
    user = (st.session_state.get("sb_user") or {})
    meta = user.get("user_metadata") or {}
    r = (meta.get("app_role") or "").strip().lower()
    return r if r in {"admin","user","member","viewer"} else "viewer"
def current_username() -> str:
    user = (st.session_state.get("sb_user") or {})
    meta = user.get("user_metadata") or {}
    return (meta.get("username") or "").strip()
def is_readonly() -> bool:
    return bool(st.secrets.get("app", {}).get("force_readonly", False))
def require_role(*allowed):
    if current_role() not in allowed:
        st.error("Onvoldoende rechten."); st.stop()

# ────────────────────────────── DB helpers (duikers/duiken/afrekening)
def list_plaatsen() -> list[str]:
    res = run_db(lambda c: c.table("duikplaatsen").select("plaats").order("plaats").execute(), what="duikplaatsen")
    return [r["plaats"] for r in (res.data or [])]

def add_plaats(p:str):
    if is_readonly(): raise Exception("read-only")
    run_db(lambda c: c.table("duikplaatsen").insert({"plaats": p}).execute(), what="duikplaatsen insert")

def list_duikers_weergave() -> list[str]:
    res = run_db(lambda c: c.table("duikers").select("voornaam, achternaam, naam").execute(), what="duikers select")
    rows = res.data or []
    out=[]
    for r in rows:
        vn, an = (r.get("voornaam") or "").strip(), (r.get("achternaam") or "").strip()
        out.append(f"{an}, {vn}".strip(", ") if (vn or an) else (r.get("naam") or "").strip())
    def key(x):
        if "," in x:
            an,vn=[p.strip() for p in x.split(",",1)]
            return (an.lower(), vn.lower())
        parts=x.split()
        return (parts[-1].lower() if parts else "", " ".join(parts[:-1]).lower())
    return sorted([o for o in out if o], key=key)

def add_duiker_split(vn:str, an:str, rest:float=0.0):
    if is_readonly(): raise Exception("read-only")
    payload = {"voornaam":vn.strip(),"achternaam":an.strip(),"naam":f"{vn} {an}".strip(),"rest_saldo":float(rest)}
    run_db(lambda c: c.table("duikers").insert(payload).execute(), what="duikers insert")

def delete_duikers(labels:list[str]):
    if is_readonly(): return (False,0,"read-only")
    deleted=0
    try:
        for disp in labels:
            if "," in disp:
                an,vn=[p.strip() for p in disp.split(",",1)]
                run_db(lambda c: c.table("duikers").delete().eq("voornaam",vn).eq("achternaam",an).execute(),
                       what="duikers delete")
            else:
                run_db(lambda c: c.table("duikers").delete().eq("naam",disp).execute(), what="duikers delete")
            deleted+=1
        return True,deleted,None
    except Exception as e:
        return False,0,str(e)

def save_duiken(rows):
    if is_readonly(): raise Exception("read-only")
    if rows: run_db(lambda c: c.table("duiken").insert(rows).execute(), what="duiken insert")

def fetch_duiken(filters=None)->pd.DataFrame:
    def _go(c):
        q=c.table("duiken").select("*")
        if filters:
            for k,v in filters.items():
                if v is None: continue
                if k=="datum_gte": q=q.gte("datum",v)
                elif k=="datum_lte": q=q.lte("datum",v)
                elif k=="plaats_eq": q=q.eq("plaats",v)
                elif k=="duikcode_eq": q=q.eq("duikcode",v)
                elif k=="duiker_eq": q=q.eq("duiker",v)
        return q.order("datum",desc=True).order("plaats").order("duikcode").order("duiker").execute()
    res = run_db(_go, what="duiken select")
    return pd.DataFrame(res.data or [])

def delete_duiken_by_ids(ids):
    if is_readonly(): raise Exception("read-only")
    if ids: run_db(lambda c: c.table("duiken").delete().in_("id", ids).execute(), what="duiken delete")

def get_rest_saldo(vn:str, an:str)->float:
    res = run_db(lambda c: c.table("duikers").select("rest_saldo").eq("voornaam",vn.strip()).eq("achternaam",an.strip()).limit(1).execute(),
                 what="duikers rest")
    rows=res.data or []
    return float((rows[0] or {}).get("rest_saldo",0)) if rows else 0.0

def set_rest_saldo(vn:str, an:str, val:float):
    if is_readonly(): raise Exception("read-only")
    run_db(lambda c: c.table("duikers").update({"rest_saldo":float(val)}).eq("voornaam",vn.strip()).eq("achternaam",an.strip()).execute(),
           what="duikers update rest")

def insert_afrekening(row:dict):
    if is_readonly(): raise Exception("read-only")
    run_db(lambda c: c.table("afrekeningen").insert(row).execute(), what="afrekeningen insert")

# ────────────────────────────── Ledenbeheer helpers
BREVET_CHOICES = ['k1','1ster','2ster','3ster','4ster','as-Inst','1*Ins','2*Ins','3*Ins']
ROLE_CHOICES = ['admin','user','member','viewer']

def list_leden_df()->pd.DataFrame:
    res = run_db(lambda c: c.table("leden").select("*").order("achternaam").order("voornaam").execute(),
                 what="leden select")
    return pd.DataFrame(res.data or [])

def upsert_lid(payload:dict):
    if is_readonly(): raise Exception("read-only")
    # upsert op email
    run_db(lambda c: c.table("leden").upsert(payload, on_conflict="email").execute(), what="leden upsert")

def rpc_admin_set_role(email:str)->bool:
    # roept SECURITY DEFINER functie aan, vereist admin-JWT (app_role=admin)
    try:
        run_db(lambda c: c.rpc("admin_set_auth_role", {"p_email": email}).execute(), what="rpc admin_set_auth_role")
        return True
    except Exception as e:
        st.error(f"Rol syncen naar Auth mislukt voor {email}: {e}")
        return False

def rpc_admin_sync_all()->bool:
    try:
        run_db(lambda c: c.rpc("admin_sync_all_roles").execute(), what="rpc admin_sync_all_roles")
        return True
    except Exception as e:
        st.error(f"Bulk rol-sync mislukt: {e}")
        return False

# ────────────────────────────── Activiteiten helpers
def leden_van_username(username:str):
    if not username: return None
    try:
        res = run_db(lambda c: c.table("leden").select("*").eq("username", username).limit(1).execute(),
                     what="leden by username")
        rows=res.data or []
        return rows[0] if rows else None
    except Exception:
        return None

def list_activiteiten(upcoming_only=True):
    def _go(c):
        q=c.table("activiteiten").select("*")
        if upcoming_only:
            q=q.gte("datum", datetime.date.today().isoformat())
        return q.order("datum").order("tijd").execute()
    res = run_db(_go, what="activiteiten select")
    return pd.DataFrame(res.data or [])

def add_activiteit(titel, omschrijving, datum, tijd, locatie, meal_options, created_by):
    if is_readonly(): raise Exception("read-only")
    payload = {
        "titel": titel.strip(),
        "omschrijving": (omschrijving or "").strip(),
        "datum": datum.isoformat(),
        "tijd": tijd.isoformat() if tijd else None,
        "locatie": (locatie or "").strip() or None,
        "meal_options": meal_options or None,
        "created_by": created_by or None
    }
    run_db(lambda c: c.table("activiteiten").insert(payload).execute(), what="activiteiten insert")

def get_signups(activiteit_id:str)->pd.DataFrame:
    res = run_db(lambda c: c.table("activity_signups").select("*").eq("activiteit_id", activiteit_id).order("signup_ts").execute(),
                 what="signups select")
    df = pd.DataFrame(res.data or [])
    expected = ["id","activiteit_id","username","lid_id","status","eating","meal_choice","signup_ts"]
    for col in expected:
        if col not in df.columns: df[col]=None
    try: df["signup_ts"]=pd.to_datetime(df["signup_ts"], errors="coerce")
    except Exception: pass
    return df

def upsert_signup(activiteit_id, username, lid_id, status, eating, meal_choice):
    if is_readonly(): raise Exception("read-only")
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

# ────────────────────────────── UI helpers
def appbar(suffix:str):
    col1,col2,col3 = st.columns([5,3,2])
    with col1: st.markdown("<b>ANWW Duikapp</b>", unsafe_allow_html=True)
    with col2: st.markdown(f"<div class='badge'>{current_username() or '—'} · {current_role()}</div>", unsafe_allow_html=True)
    with col3:
        if st.button("Uitloggen", key=f"logout_{suffix}"):
            try: sb_anon.auth.sign_out()
            except Exception: pass
            for k in ["sb_session","sb_user"]: st.session_state.pop(k, None)
            st.rerun()

# ────────────────────────────── Pagina’s
def login_page():
    st.title("ANWW Duikapp")
    st.caption("Log in met je Supabase account. Je rol bepaalt toegang.")

    with st.form("auth_form_main", clear_on_submit=False):
        email = st.text_input("E-mail", key="auth_email")
        pw = st.text_input("Wachtwoord", type="password", key="auth_pw")
        c1,c2 = st.columns([1,1])
        with c1: submitted = st.form_submit_button("Login", type="primary")
        with c2: forgot = st.form_submit_button("Wachtwoord vergeten?")

    if forgot:
        if not email:
            st.warning("Vul eerst je e-mailadres in en klik dan opnieuw.")
            return
        try:
            # evt: redirect_to=st.secrets.get("auth", {}).get("reset_redirect_to")
            sb_anon.auth.reset_password_email(email)
            st.success("Als dit e-mailadres bestaat, is er een reset-link verzonden.")
        except Exception as e:
            st.error(f"Kon geen reset-mail sturen: {e}")
        return

    if not submitted: return
    if not email or not pw:
        st.error("Vul e-mail en wachtwoord in."); return
    try:
        auth = sb_anon.auth.sign_in_with_password({"email": email, "password": pw})
        if not auth or not auth.session:
            st.error("Login mislukt."); return
        st.session_state["sb_session"] = {
            "access_token": auth.session.access_token,
            "refresh_token": auth.session.refresh_token,
        }
        st.session_state["sb_user"] = {
            "id": auth.user.id,
            "email": auth.user.email,
            "user_metadata": auth.user.user_metadata or {},
        }
        st.success("Ingelogd."); st.rerun()
    except Exception as e:
        st.error(f"Login fout: {e}")

def page_duiken():
    require_role("admin","user")
    if is_readonly(): st.warning("Read-only modus actief — je kunt niet opslaan.")
    appbar("duiken")

    plaatsen_list = list_plaatsen()
    datum = st.date_input("Datum", datetime.date.today(), key="duiken_datum", format="DD/MM/YYYY")
    duikcode = st.text_input("Duikcode (optioneel)", key="duiken_code")
    plaats = st.selectbox("Duikplaats", ["— kies —"] + plaatsen_list, index=0, key="duiken_plaats")
    labels = list_duikers_weergave()
    sel = st.multiselect("Kies duikers", labels, key="duiken_sel_duikers")

    if current_role()=="admin":
        with st.expander("➕ Duiker toevoegen (snel)"):
            c1,c2,c3 = st.columns([1,1,1])
            vn = c1.text_input("Voornaam", key="new_vn")
            an = c2.text_input("Achternaam", key="new_an")
            rest0 = c3.number_input("Start rest (€)", min_value=0.0, step=0.5, value=0.0, key="new_rest")
            if st.button("Toevoegen", key="btn_add_duiker"):
                if vn or an:
                    try: add_duiker_split(vn, an, rest0); st.success(f"Toegevoegd: {vn} {an}".strip()); st.rerun()
                    except Exception as e: st.error(f"Mislukt: {e}")
                else: st.warning("Geef minstens voornaam of achternaam.")

        with st.expander("➕ Duikplaats toevoegen"):
            np = st.text_input("Nieuwe duikplaats", key="new_plaats")
            if st.button("Duikplaats toevoegen", key="btn_add_plaats"):
                if np and (np not in plaatsen_list):
                    try: add_plaats(np); st.success(f"Duikplaats '{np}' toegevoegd."); st.rerun()
                    except Exception as e: st.error(f"Mislukt: {e}")
                else: st.warning("Leeg of al bestaand.")

    can_save = (plaats and plaats != "— kies —" and sel)
    if st.button("Opslaan duik(en)", type="primary", disabled=(not can_save or is_readonly()), key="duiken_save"):
        rows = [{"datum": datum.isoformat(), "plaats": plaats, "duiker": lab.replace(", ", " "), "duikcode": duikcode or ""} for lab in sel]
        try: save_duiken(rows); st.success(f"{len(sel)} duik(en) opgeslagen.")
        except Exception as e: st.error(f"Opslaan mislukt: {e}")

def page_overzicht():
    require_role("admin","user")
    appbar("overzicht")
    df = fetch_duiken()
    if df.empty: st.info("Nog geen duiken geregistreerd."); return

    if "id" not in df.columns:
        st.warning("Let op: kolom 'id' ontbreekt in 'duiken' — verwijderen werkt niet.")
        df["id"]=None

    df["Datum"]=pd.to_datetime(df["datum"]).dt.date
    df["Plaats"]=df["plaats"]; df["Duiker"]=df["duiker"]; df["Duikcode"]=df["duikcode"].fillna("")

    c1,c2,c3,c4=st.columns([1,1,1,2])
    min_d,max_d=df["Datum"].min(), df["Datum"].max()
    rng=c1.date_input("Datumrange",(min_d,max_d), format="DD/MM/YYYY")
    plaatsen=["Alle"]+sorted(df["Plaats"].dropna().unique().tolist())
    pf=c2.selectbox("Duikplaats", plaatsen, index=0)
    codes=["Alle"]+sorted([c if c else "—" for c in df["Duikcode"].unique().tolist()])
    cf=c3.selectbox("Duikcode", codes, index=0)
    duikers=["Alle"]+sorted(df["Duiker"].dropna().unique().tolist())
    dfilt=c4.selectbox("Duiker", duikers, index=0)

    start,end = rng if isinstance(rng,tuple) else (min_d,max_d)
    f=df[(df["Datum"]>=start)&(df["Datum"]<=end)].copy()
    if pf!="Alle": f=f[f["Plaats"]==pf]
    if cf!="Alle": f=f[f["Duikcode"].replace({"":"—"})==cf]
    if dfilt!="Alle": f=f[f["Duiker"]==dfilt]
    f=f.sort_values(["Datum","Plaats","Duikcode","Duiker","id"]).reset_index(drop=True)

    view=f[["Datum","Plaats","Duiker","Duikcode"]].copy()
    view["Datum"]=pd.to_datetime(view["Datum"]).dt.strftime("%d/%m/%Y")
    st.dataframe(view, use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Duiken verwijderen (volgens huidige filter)")
    def _label(row):
        dc=row.get("Duikcode") or row.get("duikcode") or ""; dc=dc if dc else "—"
        return f"{row['Datum'].strftime('%d/%m/%Y')} · {row['Plaats']} · {row['Duiker']} · {dc}"
    f2=f.copy(); f2["Datum"]=pd.to_datetime(f2["Datum"]).dt.date
    options,id_map=[],{}
    for _,r in f2.iterrows():
        lbl=_label(r); lbl2=lbl if lbl not in id_map else f"{lbl}  (#ID:{r['id']})"
        options.append(lbl2); id_map[lbl2]=r["id"]
    sel=st.multiselect("Kies duiken om te verwijderen", options, key="ovz_del")
    if st.button("Verwijder geselecteerde", disabled=(len(sel)==0 or is_readonly()), key="btn_del_duiken"):
        ids=[id_map[l] for l in sel if id_map[l] is not None]
        if not ids: st.warning("Geen geldige ID's.")
        else:
            try: delete_duiken_by_ids(ids); st.success(f"Verwijderd: {len(ids)} duik(en)."); st.rerun()
            except Exception as e: st.error(f"Verwijderen mislukt: {e}")

    st.divider()
    st.subheader("Export (Excel) — huidige filter")
    out=io.BytesIO()
    with pd.ExcelWriter(out, engine="openpyxl") as w:
        view.to_excel(w, index=False, sheet_name="Duiken")
    st.download_button("⬇️ Download Excel", data=out.getvalue(), file_name="duiken_export.xlsx",
                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

def page_afrekening():
    require_role("admin","user","viewer")
    appbar("afrekening")
    df=fetch_duiken()
    if df.empty: st.info("Nog geen duiken geregistreerd."); return

    df["Datum"]=pd.to_datetime(df["datum"]).dt.date
    df["Plaats"]=df["plaats"]; df["Duiker"]=df["duiker"]

    c1,c2,c3,c4=st.columns(4)
    min_d,max_d=df["Datum"].min(), df["Datum"].max()
    rng=c1.date_input("Periode",(min_d,max_d), key="afr_range", format="DD/MM/YYYY")
    bedrag=c2.number_input("Bedrag per duik (€)", min_value=0.0, step=0.5, value=5.0, key="afr_bedrag")
    pf=c3.selectbox("Duikplaats (optioneel)", ["Alle"]+sorted(df["Plaats"].dropna().unique().tolist()), index=0, key="afr_plaats")
    blok=c4.number_input("Blokgrootte (€)", min_value=0.0, step=10.0, value=30.0, key="afr_blok")

    start,end = rng if isinstance(rng,tuple) else (min_d,max_d)
    m=(df["Datum"]>=start)&(df["Datum"]<=end)
    if pf!="Alle": m &= df["Plaats"]==pf
    s=df.loc[m].copy()
    if s.empty: st.warning("Geen duiken in de gekozen periode/filters."); return

    per = s.groupby("Duiker").size().reset_index(name="AantalDuiken")
    per["Bruto"]=(per["AantalDuiken"]*bedrag).round(2)

    try:
        ddf = run_db(lambda c: c.table("duikers").select("voornaam, achternaam, naam, rest_saldo").execute(),
                     what="duikers join").data or []
        ddf = pd.DataFrame(ddf)
    except Exception:
        ddf = pd.DataFrame([])

    def split_guess(disp:str):
        parts=(disp or "").split()
        if len(parts)<=1: return "", disp or ""
        return parts[0], " ".join(parts[1:])

    vns,ans,rests=[],[],[]
    for disp in per["Duiker"].astype(str).tolist():
        vn,an,rest="","",0.0
        if not ddf.empty:
            row=ddf.loc[ddf["naam"]==disp]
            if not row.empty:
                vn=(row.iloc[0].get("voornaam") or "").strip()
                an=(row.iloc[0].get("achternaam") or "").strip()
                rest=float(row.iloc[0].get("rest_saldo") or 0)
            else:
                vn,an=split_guess(disp)
                row2=ddf.loc[(ddf["voornaam"].fillna("").str.strip()==vn)&(ddf["achternaam"].fillna("").str.strip()==an)]
                if not row2.empty: rest=float(row2.iloc[0].get("rest_saldo") or 0)
        else:
            vn,an=split_guess(disp)
        vns.append(vn); ans.append(an); rests.append(round(float(rest),2))

    per["Voornaam"]=vns; per["Achternaam"]=ans; per["RestOud"]=rests
    per["Totaal"]=(per["Bruto"]+per["RestOud"]).round(2)

    def calc_blokken(total:float):
        if blok<=0: return 0,0.0,round(total,2)
        n=math.floor(total/blok); uit=round(n*blok,2); rest=round(total-uit,2)
        return n,uit,rest

    rows=[]
    for _,r in per.iterrows():
        n,uit,rest=calc_blokken(float(r["Totaal"]))
        rows.append({**r.to_dict(),"Blokken":n,"UitTeBetalen":uit,"RestNieuw":rest})
    per=pd.DataFrame(rows).sort_values(["Achternaam","Voornaam","Duiker"], na_position="last").reset_index(drop=True)

    st.subheader("Afrekening per duiker")
    show=["Achternaam","Voornaam","AantalDuiken","Bruto","RestOud","Totaal","Blokken","UitTeBetalen","RestNieuw"]
    st.dataframe(per[show], use_container_width=True, hide_index=True)

    if current_role() in {"admin","user"} and not is_readonly():
        st.divider(); st.subheader("Historiek vastleggen / Markeer als betaald")
        per["select"]=False
        for i in range(len(per)):
            label=f"{per.at[i,'Achternaam']}, {per.at[i,'Voornaam']}"
            per.at[i,"select"]=st.checkbox(label, key=f"sel_pay_{i}")
        if st.button("Markeer geselecteerde als betaald", key="afr_save"):
            try:
                sel=per[per["select"]==True]
                if sel.empty: st.warning("Geen duikers geselecteerd.")
                else:
                    for _,r in sel.iterrows():
                        row={
                            "voornaam":(r["Voornaam"] or "").strip(),
                            "achternaam":(r["Achternaam"] or "").strip(),
                            "periode_start":start,"periode_end":end,
                            "bedrag_per_duik":float(bedrag),"blokgrootte":float(blok),
                            "aantal_duiken":int(r["AantalDuiken"]),"bruto_bedrag":float(r["Bruto"]),
                            "rest_oud":float(r["RestOud"]),"blokken":int(r["Blokken"]),
                            "uit_te_betalen":float(r["UitTeBetalen"]),"rest_nieuw":float(r["RestNieuw"]),
                            "betaald_op":dt.utcnow().isoformat()
                        }
                        insert_afrekening(row)
                        if row["voornaam"] or row["achternaam"]:
                            set_rest_saldo(row["voornaam"], row["achternaam"], row["rest_nieuw"])
                    st.success(f"Afrekening geregistreerd voor {len(sel)} duiker(s)."); st.rerun()
            except Exception as e:
                st.error(f"Registratie mislukt: {e}")

    st.divider()
    st.subheader("Export (Excel)")
    out=io.BytesIO()
    with pd.ExcelWriter(out, engine="openpyxl") as w:
        per[show].to_excel(w, index=False, sheet_name="Afrekening")
        s.sort_values(["Datum","Plaats","duikcode","Duiker"]).to_excel(w, index=False, sheet_name="Detail")
    st.download_button("⬇️ Download Afrekening (Excel)", data=out.getvalue(), file_name="Afrekening.xlsx",
                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

def page_beheer():
    require_role("admin")
    if is_readonly(): st.warning("Read-only modus actief — wijzigingen zijn geblokkeerd.")
    appbar("beheer")
    tabs = st.tabs(["Ledenbeheer","Duikers","Duikplaatsen","Back-up & export"])

    # ── Ledenbeheer
    with tabs[0]:
        st.subheader("Leden aanmaken/bewerken")
        df = list_leden_df()
        if not df.empty:
            df_view = df.copy()
            df_view = df_view[["voornaam","achternaam","email","duikbrevet","username","desired_role","opt_in_weekly","actief","created_at"]] \
                       if "created_at" in df_view.columns else \
                       df_view[["voornaam","achternaam","email","duikbrevet","username","desired_role","opt_in_weekly","actief"]]
            st.dataframe(df_view, use_container_width=True, hide_index=True)
        else:
            st.info("Nog geen leden.")

        st.divider()
        st.markdown("### Lid toevoegen / bijwerken")
        c1,c2,c3 = st.columns(3)
        with c1:
            vn = st.text_input("Voornaam", key="lid_vn")
            an = st.text_input("Achternaam", key="lid_an")
            email = st.text_input("E-mail", key="lid_email")
        with c2:
            brevet = st.selectbox("Duikbrevet", options=["(geen)"]+BREVET_CHOICES, index=0, key="lid_brevet")
            username = st.text_input("Username", help="bv. voornaam.achternaam", key="lid_username")
        with c3:
            role = st.selectbox("Gewenste rol", options=["(geen)"]+ROLE_CHOICES, index=0, key="lid_role")
            optin = st.toggle("Wekelijkse mail", value=True, key="lid_optin")

        if st.button("Bewaar lid (upsert op e-mail)", type="primary", key="btn_save_lid", disabled=is_readonly()):
            if not email:
                st.warning("E-mail is verplicht (upsert-sleutel).")
            else:
                payload = {
                    "email": email.strip(),
                    "voornaam": (vn or "").strip(),
                    "achternaam": (an or "").strip(),
                    "duikbrevet": None if brevet=="(geen)" else brevet,
                    "username": (username or "").strip() or None,
                    "desired_role": None if role=="(geen)" else role,
                    "opt_in_weekly": bool(optin),
                    "actief": True
                }
                try:
                    upsert_lid(payload)
                    st.success("Lid bewaard. (Duikerslijst wordt automatisch gesynchroniseerd op basis van duikbrevet.)")
                    st.rerun()
                except Exception as e:
                    st.error(f"Bewaren mislukt: {e}")

        st.divider()
        st.markdown("### Rol naar Auth schrijven")
        cA,cB = st.columns([1,1])
        with cA:
            email_sync = st.text_input("E-mail om rol te syncen", key="sync_one_email")
            if st.button("Sync rol voor dit e-mailadres", key="btn_sync_one", disabled=is_readonly()):
                if not email_sync:
                    st.warning("Geef een e-mailadres op.")
                else:
                    if rpc_admin_set_role(email_sync.strip()):
                        st.success("Rol/username naar Auth gezet (indien user bestaat). Log daarna even uit & opnieuw in.")
        with cB:
            if st.button("Bulk: sync alle rollen (op basis van leden.desired_role)", key="btn_sync_all", disabled=is_readonly()):
                if rpc_admin_sync_all():
                    st.success("Bulk-rolsync uitgevoerd.")

    # ── Duikers
    with tabs[1]:
        res = run_db(lambda c: c.table("duikers").select("voornaam, achternaam, naam, rest_saldo").execute(),
                     what="duikers select (beheer)")
        ddf = pd.DataFrame(res.data or [])
        st.subheader("Duikers (afgeleid uit leden met duikbrevet)")
        if not ddf.empty:
            v = ddf.rename(columns={"voornaam":"Voornaam","achternaam":"Achternaam","rest_saldo":"Rest (start)"})
            st.dataframe(v, use_container_width=True, hide_index=True)
        else:
            st.caption("Nog geen duikers — geef duikbrevet aan een lid in Ledenbeheer.")

        st.divider()
        st.subheader("Duikers handmatig verwijderen (uitzondering)")
        sel_duikers = st.multiselect("Kies duikers om te verwijderen",
                                     ddf["achternaam"].fillna("") + ", " + ddf["voornaam"].fillna("") if not ddf.empty else [])
        if st.button("Verwijder geselecteerde duikers", disabled=(len(sel_duikers)==0 or is_readonly()), key="btn_del_duikers"):
            ok, n, err = delete_duikers(sel_duikers)
            if ok: st.success(f"Verwijderd: {n} duiker(s)."); st.rerun()
            else: st.error(f"Verwijderen mislukt: {err}")

    # ── Duikplaatsen
    with tabs[2]:
        plaatsen = list_plaatsen()
        st.subheader("Duikplaatsen (overzicht)")
        st.dataframe(pd.DataFrame({"Plaats": plaatsen}), use_container_width=True, hide_index=True)

        st.subheader("Duikplaatsen verwijderen")
        sel_pl = st.multiselect("Kies duikplaatsen om te verwijderen", plaatsen, key="beheer_del_pl")
        if st.button("Verwijder geselecteerde duikplaatsen", disabled=(len(sel_pl)==0 or is_readonly()), key="btn_del_pl"):
            try:
                run_db(lambda c: c.table("duikplaatsen").delete().in_("plaats", sel_pl).execute(), what="duikplaatsen delete")
                st.success(f"Verwijderd: {len(sel_pl)} duikplaats(en)."); st.rerun()
            except Exception as e:
                st.error(f"Verwijderen mislukt: {e}")

        st.divider()
        st.subheader("Nieuwe duikplaats")
        np = st.text_input("Nieuwe duikplaats", key="beheer_new_pl")
        if st.button("Toevoegen aan duikplaatsen", disabled=is_readonly(), key="btn_add_pl"):
            if np and (np not in plaatsen):
                try: add_plaats(np); st.success(f"Duikplaats '{np}' toegevoegd."); st.rerun()
                except Exception as e: st.error(f"Toevoegen mislukt: {e}")
            else: st.warning("Leeg of al bestaand.")

    # ── Back-up
    with tabs[3]:
        st.info("Download een back-up (Excel) van de tabellen.")
        if st.button("Maak back-up (Excel)", disabled=is_readonly(), key="btn_backup"):
            out=io.BytesIO()
            duikers = run_db(lambda c: c.table("duikers").select("*").execute(), what="duikers select (backup)")
            plaatsen_df = run_db(lambda c: c.table("duikplaatsen").select("*").execute(), what="duikplaatsen select (backup)")
            duiken = run_db(lambda c: c.table("duiken").select("*").execute(), what="duiken select (backup)")
            leden = run_db(lambda c: c.table("leden").select("*").execute(), what="leden select (backup)")
            df_duikers=pd.DataFrame(duikers.data or [])
            df_plaatsen=pd.DataFrame(plaatsen_df.data or [])
            df_duiken=pd.DataFrame(duiken.data or [])
            df_leden=pd.DataFrame(leden.data or [])
            stamp=dt.utcnow().strftime("%Y%m%d_%H%M%S")
            with pd.ExcelWriter(out, engine="openpyxl") as w:
                df_duikers.to_excel(w, index=False, sheet_name="duikers")
                df_plaatsen.to_excel(w, index=False, sheet_name="duikplaatsen")
                df_duiken.to_excel(w, index=False, sheet_name="duiken")
                df_leden.to_excel(w, index=False, sheet_name="leden")
            st.download_button("⬇️ Download back-up", data=out.getvalue(),
                               file_name=f"anww_backup_{stamp}.xlsx",
                               mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

def page_activiteiten():
    require_role("admin","user","member")  # viewer ziet niet
    if is_readonly(): st.warning("Read-only modus actief — inschrijven kan geblokkeerd zijn.")
    appbar("activiteiten")
    st.header("Kalender & Inschrijvingen")

    # Admin: nieuwe activiteit
    if current_role()=="admin":
        with st.expander("➕ Nieuwe activiteit"):
            c1,c2 = st.columns([2,1])
            with c1:
                titel = st.text_input("Titel*", key="act_titel")
                omschr = st.text_area("Omschrijving", key="act_oms")
            with c2:
                datum = st.date_input("Datum*", value=datetime.date.today(), format="DD/MM/YYYY", key="act_datum")
                tijd = st.time_input("Tijd (optioneel)", value=None, key="act_tijd")
                locatie = st.text_input("Locatie", key="act_loc")
            st.caption("Maaltijdopties (max. 3, optioneel)")
            m1,m2,m3 = st.columns(3)
            with m1: mo1 = st.text_input("Optie 1", key="act_m1")
            with m2: mo2 = st.text_input("Optie 2", key="act_m2")
            with m3: mo3 = st.text_input("Optie 3", key="act_m3")
            if st.button("Activiteit toevoegen", type="primary", key="act_add"):
                if not titel or not datum:
                    st.warning("Titel en datum zijn verplicht.")
                else:
                    meal_opts = [x.strip() for x in [mo1, mo2, mo3] if x and x.strip()]
                    try:
                        add_activiteit(titel, omschr, datum, tijd, locatie, meal_opts or None, created_by=current_username())
                        st.success("Activiteit aangemaakt."); st.rerun()
                    except Exception as e:
                        st.error(f"Mislukt: {e}")

    # Lijst activiteiten
    try:
        df = list_activiteiten(upcoming_only=True)
    except Exception as e:
        st.warning(f"Kan activiteiten niet laden (RLS/tabellen?): {e}")
        return
    if df.empty:
        st.info("Geen (toekomstige) activiteiten."); return

    my_username = current_username()
    my_lid = leden_van_username(my_username)
    my_lid_id = (my_lid or {}).get("id")

    for _, row in df.sort_values(["datum","tijd"], na_position="last").iterrows():
        s = get_signups(row["id"])

        myrow=None
        if my_username:
            tmp=s.loc[s["username"]==my_username]
            if not tmp.empty: myrow=tmp
        if (myrow is None or myrow.empty) and my_lid_id:
            tmp=s.loc[s["lid_id"]==my_lid_id]
            if not tmp.empty: myrow=tmp
        my_status = (myrow.iloc[0]["status"] if (myrow is not None and not myrow.empty) else None)
        badge = "🟢 ingeschreven" if my_status=="yes" else ("🔴 niet ingeschreven" if my_status=="no" else "⚪ nog niet gekozen")

        titel = f"{row['titel']} — {pd.to_datetime(row['datum']).strftime('%d/%m/%Y')}"
        if row.get('tijd'): titel += f" · {row['tijd']}"

        with st.expander(f"{titel}   ·   {badge}", expanded=False):
            if row.get("locatie"): st.caption(row["locatie"])
            if row.get("omschrijving"): st.write(row["omschrijving"])
            coming = s.loc[s["status"]=="yes"].sort_values("signup_ts")
            notcoming = s.loc[s["status"]=="no"].sort_values("signup_ts")

            colA,colB=st.columns(2)
            with colA:
                st.markdown("**Komen (op volgorde van inschrijving):**")
                if coming.empty: st.caption("Nog niemand.")
                else:
                    for _,ss in coming.iterrows():
                        meal = f" · eet: {ss['meal_choice']}" if ss.get("eating") else ""
                        st.write(f"- {ss.get('username') or 'lid'}{meal}")
            with colB:
                st.markdown("**Niet komen:**")
                if notcoming.empty: st.caption("Nog niemand.")
                else:
                    for _,ss in notcoming.iterrows():
                        st.write(f"- {ss.get('username') or 'lid'}")

            st.divider()
            st.markdown("**Mijn inschrijving**")
            prev_eating=False; prev_meal=None
            if myrow is not None and not myrow.empty:
                if pd.notna(myrow.iloc[0].get("eating")): prev_eating = bool(myrow.iloc[0].get("eating"))
                pm = myrow.iloc[0].get("meal_choice"); prev_meal = pm if isinstance(pm,str) and pm.strip() else None
            init_index = 0 if my_status in (None,"yes") else 1
            status = st.radio("Status", options=["Ik kom","Ik kom niet"], horizontal=True, key=f"st_{row['id']}", index=init_index)
            eating=None; meal_choice=None; meal_opts = row.get("meal_options") or []
            if status=="Ik kom":
                eating = st.checkbox("Ik eet mee", value=prev_eating, key=f"eat_{row['id']}")
                if eating and meal_opts:
                    default_ix=0
                    if prev_meal and prev_meal in meal_opts: default_ix=meal_opts.index(prev_meal)+1
                    mc = st.selectbox("Kies je maaltijd", ["— kies —"]+meal_opts, index=default_ix, key=f"meal_{row['id']}")
                    meal_choice = None if mc=="— kies —" else mc
            if st.button("Bewaar mijn keuze", key=f"save_{row['id']}", type="primary", disabled=is_readonly()):
                try:
                    upsert_signup(row["id"], my_username or None, my_lid_id or None,
                                  "yes" if status=="Ik kom" else "no", eating, meal_choice)
                    st.success("Inschrijving bijgewerkt."); st.rerun()
                except Exception as e:
                    st.error(f"Opslaan mislukt: {e}")

# ────────────────────────────── Profiel
def set_opt_in_weekly_by_lid_id(lid_id:str, opt_in:bool):
    run_db(lambda c: c.table("leden").update({"opt_in_weekly": bool(opt_in)}).eq("id", lid_id).execute(),
           what="leden update opt_in_weekly")

def page_profiel():
    appbar("profiel")
    st.header("Mijn profiel")

    user=st.session_state.get("sb_user") or {}
    email=user.get("email") or "—"
    meta=user.get("user_metadata") or {}
    role=(meta.get("app_role") or "viewer").lower()
    uname=(meta.get("username") or "") or "—"

    c1,c2=st.columns(2)
    with c1:
        st.markdown(f"**E-mail:** {email}")
        st.markdown(f"**Gebruikersnaam:** {uname}")
        st.markdown(f"**Rol:** {role}")
    with c2:
        st.info("Ben je je wachtwoord vergeten? Gebruik de link op het login-scherm. "
                "Ben je ingelogd, dan kan je hieronder je wachtwoord wijzigen.")

    my_lid = leden_van_username((meta.get("username") or "").strip())
    if my_lid:
        st.divider(); st.subheader("Wekelijkse mail")
        cur = bool(my_lid.get("opt_in_weekly", True))
        new_val = st.toggle("Ik wil de wekelijkse activiteitenmail ontvangen", value=cur, key="optin_weekly_toggle")
        if new_val != cur and st.button("Bewaar voorkeur", key="save_optin"):
            try: set_opt_in_weekly_by_lid_id(my_lid["id"], new_val); st.success("Voorkeur opgeslagen."); st.rerun()
            except Exception as e: st.error(f"Opslaan mislukt: {e}")
    else:
        st.divider(); st.caption("Geen ledenrecord gevonden voor je gebruikersnaam.")

    st.divider(); st.subheader("Wachtwoord wijzigen")
    npw1 = st.text_input("Nieuw wachtwoord", type="password", key="pw1")
    npw2 = st.text_input("Bevestig nieuw wachtwoord", type="password", key="pw2")
    if st.button("Wijzig wachtwoord", key="btn_change_pw"):
        if not npw1 or len(npw1)<8:
            st.warning("Kies een wachtwoord van minstens 8 tekens.")
        elif npw1 != npw2:
            st.warning("Wachtwoorden komen niet overeen.")
        else:
            try:
                sess=st.session_state.get("sb_session") or {}
                sb_anon.auth.set_session(sess.get("access_token"), sess.get("refresh_token"))
                sb_anon.auth.update_user({"password": npw1})
                st.success("Wachtwoord gewijzigd. Log uit en opnieuw in met je nieuwe wachtwoord.")
            except Exception as e:
                st.error(f"Kon wachtwoord niet wijzigen: {e}")

# ────────────────────────────── Main (Activiteiten eerst)
def main():
    if not st.session_state.get("sb_session"):
        login_page(); return

    role=current_role()
    st.markdown(
        f"<div class='badge'>Ingelogd als: <b>{current_username() or '—'}</b> · Rol: <b>{role}</b>"
        + (" · READ-ONLY (noodslot)" if is_readonly() else "")
        + f" · Build: {APP_BUILD}</div>", unsafe_allow_html=True
    )

    if role=="admin" and not is_readonly():
        tabs=st.tabs(["Activiteiten","Ledenbeheer","Duiken invoeren","Overzicht","Afrekening","Mijn profiel"])
        with tabs[0]: page_activiteiten()
        with tabs[1]: page_beheer()
        with tabs[2]: page_duiken()
        with tabs[3]: page_overzicht()
        with tabs[4]: page_afrekening()
        with tabs[5]: page_profiel()
    elif role=="user":
        tabs=st.tabs(["Activiteiten","Duiken invoeren","Overzicht","Afrekening","Mijn profiel"])
        with tabs[0]: page_activiteiten()
        with tabs[1]: page_duiken()
        with tabs[2]: page_overzicht()
        with tabs[3]: page_afrekening()
        with tabs[4]: page_profiel()
    elif role=="member":
        tabs=st.tabs(["Activiteiten","Mijn profiel"])
        with tabs[0]: page_activiteiten()
        with tabs[1]: page_profiel()
    else: # viewer
        tabs=st.tabs(["Afrekening","Mijn profiel"])
        with tabs[0]: page_afrekening()
        with tabs[1]: page_profiel()

if __name__ == "__main__":
    main()
