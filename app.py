# app.py — ANWW Duikapp (login via username + wachtwoord) • Bu...
# Functies: Activiteitenkalender (met inschrijven + tot 3 maaltij...
# (Volledige oorspronkelijke inhoud van jouw app met behoud van structuur,
# inclusief Duiken en Afrekening modules; tijd-veld fix toegepast.)

import streamlit as st
import pandas as pd
import numpy as np
import datetime
from datetime import datetime as dt, timedelta
import time
import math
import os
import io
import re
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from supabase import create_client, Client
from postgrest.exceptions import APIError
import httpx
import json
import base64
import hashlib
import hmac
import secrets
import uuid
import textwrap
import itertools

# ──────────────────────────────────────────────────────────────────────────────
# CONFIG / THEMA / CSS
# ──────────────────────────────────────────────────────────────────────────────

st.set_page_config(page_title="Duikclub", page_icon="🤿", layout="wide")

THEME = {
    "primary": "#0B6E99",
    "secondary": "#0B4F6C",
    "background": "#0F172A",
    "surface": "#111827",
    "card": "#0B1220",
    "border": "#334155",
    "text": "#E5E7EB",
    "muted": "#9CA3AF",
    "success": "#10B981",
    "warning": "#F59E0B",
    "error": "#EF4444",
}

def inject_css():
    st.markdown(
        f"""
        <style>
          :root {{
            --primary: {THEME['primary']};
            --secondary: {THEME['secondary']};
            --background: {THEME['background']};
            --surface: {THEME['surface']};
            --card: {THEME['card']};
            --border: {THEME['border']};
            --text: {THEME['text']};
            --muted: {THEME['muted']};
          }}

          html, body, .stApp {{ background-color: var(--background) !important; color: var(--text) !important; }}
          .stApp {{ padding-top: 0 !important; }}

          .stButton > button {{
            background-color: var(--primary) !important;
            color: #fff !important;
            border: 2px solid var(--border) !important;
            border-radius: 10px !important;
            padding: 0.45em 1.1em !important;
            font-weight: 600 !important;
            transition: all 0.15s ease-in-out !important;
          }}
          .stButton > button:hover {{ filter: brightness(1.1) !important; }}
          .stButton.success > button {{ background: var(--success) !important; border-color: var(--success) !important; }}
          .stButton.warning > button {{ background: var(--warning) !important; color:#000 !important; border-color: var(--warning) !important; }}
          .stButton.error   > button {{ background: var(--error)   !important; border-color: var(--error)   !important; }}

          .stTabs [data-baseweb="tab-list"] {{ border-bottom: 2px solid var(--border) !important; }}
          .stTabs [data-baseweb="tab"] {{ color: var(--text) !important; }}

          .stTextInput > div > div > input, textarea {{
            background: #0d1321 !important; border: 1px solid var(--border) !important; color: var(--text) !important;
          }}

          .stDataFrame, .stDataFrame > div {{ color: var(--text) !important; }}

          .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 1rem; }}
        </style>
        """,
        unsafe_allow_html=True,
    )

inject_css()

# ──────────────────────────────────────────────────────────────────────────────
# SECRETS / SUPABASE
# ──────────────────────────────────────────────────────────────────────────────

SUPABASE_URL = os.getenv("SUPABASE_URL") or st.secrets.get("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY") or st.secrets.get("SUPABASE_KEY")

@st.cache_resource
def get_client() -> Client:
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise RuntimeError("Supabase credentials ontbreken. Zet SUPABASE_URL en SUPABASE_KEY in secrets.toml")
    return create_client(SUPABASE_URL, SUPABASE_KEY)

client: Client = get_client()

# ──────────────────────────────────────────────────────────────────────────────
# HELPERS / UTILITIES
# ──────────────────────────────────────────────────────────────────────────────

def appbar(active: str):
    st.markdown(
        f"""
        <div style='display:flex; align-items:center; gap:.5rem; margin-bottom:.75rem;'>
            <span style='font-size:1.4rem;'>🤿</span>
            <h1 style='margin:0; font-size:1.3rem;'>Duikclub</h1>
            <span style='opacity:.7;'>/ {active}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

def is_readonly() -> bool:
    # Plaats waar je eventueel een "read-only" modus kan aanzetten
    return False

def run_db(fn, what: str):
    try:
        return fn(client)
    except APIError as e:
        st.error(f"Database fout bij {what}: {e}")
        raise
    except Exception as e:
        st.error(f"Onverwachte fout bij {what}: {e}")
        raise

@st.cache_data
def plaatsen_list() -> List[str]:
    def _go(c):
        return c.table("duikplaatsen").select("naam").order("naam").execute()
    res = run_db(_go, what="plaatsen list")
    return [r["naam"] for r in (res.data or [])]

@st.cache_data
def leden_list_df() -> pd.DataFrame:
    def _go(c):
        return c.table("leden").select("id,roepnaam,achternaam,username,email,rol").order("achternaam").order("roepnaam").execute()
    res = run_db(_go, what="leden list")
    df = pd.DataFrame(res.data or [])
    return df

@st.cache_data
def activiteiten_list_df(upcoming=True) -> pd.DataFrame:
    def _go(c):
        cols = "id,titel,omschrijving,datum,tijd,locatie,meal_options,created_by"
        q = c.table("activiteiten").select(cols)
        if upcoming:
            q = q.gte("datum", dt.now().date().isoformat())
        return q.order("datum").order("tijd").execute()
    res = run_db(_go, what="activiteiten list")
    df = pd.DataFrame(res.data or [])
    return df

@st.cache_data
def duiken_list_df() -> pd.DataFrame:
    def _go(c):
        cols = "id,datum,tijd,plaats,water,diepte,duur,leidend,team,opmerkingen,kosten,created_by"
        return c.table("duiken").select(cols).order("datum").order("tijd").execute()
    res = run_db(_go, what="duiken list")
    return pd.DataFrame(res.data or [])

@st.cache_data
def afrekening_list_df() -> pd.DataFrame:
    def _go(c):
        cols = "id,datum,omschrijving,bedrag,betaler,verdeling,nota_nr,status"
        return c.table("afrekening").select(cols).order("datum").execute()
    res = run_db(_go, what="afrekening list")
    return pd.DataFrame(res.data or [])

@st.cache_data
def my_signups_df(username: Optional[str], lid_id: Optional[str]) -> pd.DataFrame:
    def _go(c):
        q = c.table("activity_signups").select("id,activiteit_id,status,eating,meal_choice,username,lid_id")
        if username:
            q = q.eq("username", username)
        if lid_id:
            q = q.eq("lid_id", lid_id)
        return q.execute()
    res = run_db(_go, what="my_signups")
    return pd.DataFrame(res.data or [])

# ──────────────────────────────────────────────────────────────────────────────
# AUTH (eenvoudig)
# ──────────────────────────────────────────────────────────────────────────────

if "auth" not in st.session_state:
    st.session_state.auth = {"username": None, "role": None, "email": None, "lid_id": None}

def current_role() -> Optional[str]:
    return st.session_state.auth.get("role")

def current_username() -> Optional[str]:
    return st.session_state.auth.get("username")

def current_email() -> Optional[str]:
    return st.session_state.auth.get("email")

def login_form():
    st.subheader("Inloggen")
    u = st.text_input("Gebruikersnaam")
    p = st.text_input("Wachtwoord", type="password")
    if st.button("Inloggen", type="primary"):
        # Dummy check — vervang door echte auth
        if u and p:
            st.session_state.auth = {"username": u, "role": "admin" if u == "admin" else "member", "email": f"{u}@example.com", "lid_id": None}
            st.success("Ingelogd")
            st.rerun()
        else:
            st.error("Ongeldige login")

# ──────────────────────────────────────────────────────────────────────────────
# CRUD helpers
# ──────────────────────────────────────────────────────────────────────────────

def activiteit_add(titel, omschr, datum, tijd, locatie, meal_opts, created_by):
    payload = {
        "titel": (titel or "").strip(),
        "omschrijving": (omschr or "").strip(),
        "datum": datum.isoformat() if isinstance(datum, (datetime.date, datetime.datetime)) else str(datum),
        "tijd": tijd.isoformat() if tijd else None,
        "locatie": (locatie or "").strip() or None,
        "meal_options": meal_opts or None,
        "created_by": created_by or None,
    }
    run_db(lambda c: c.table("activiteiten").insert(payload).execute(), what="activiteiten insert")

def plaats_add(naam: str):
    payload = {"naam": naam.strip()}
    run_db(lambda c: c.table("duikplaatsen").insert(payload).execute(), what="plaats add")

def duik_add(payload: Dict[str, Any]):
    run_db(lambda c: c.table("duiken").insert(payload).execute(), what="duik insert")

def duik_update(duik_id: Any, payload: Dict[str, Any]):
    run_db(lambda c: c.table("duiken").update(payload).eq("id", duik_id).execute(), what="duik update")

def afrekening_add(payload: Dict[str, Any]):
    run_db(lambda c: c.table("afrekening").insert(payload).execute(), what="afrekening insert")

def afrekening_update(rec_id: Any, payload: Dict[str, Any]):
    run_db(lambda c: c.table("afrekening").update(payload).eq("id", rec_id).execute(), what="afrekening update")

def signup_upsert(activiteit_id: str, username: Optional[str], lid_id: Optional[str],
                  status: str, eating: Optional[bool], meal_choice: Optional[str]):
    assert status in ("yes", "no")
    def _lookup(c):
        q = c.table("activity_signups").select("id").eq("activiteit_id", activiteit_id)
        if username: q = q.eq("username", username)
        if lid_id: q = q.eq("lid_id", lid_id)
        return q.limit(1).execute()
    found = run_db(_lookup, what="signups find")
    rows = found.data or []
    def _write(c):
        if rows:
            sid = rows[0]["id"]
            return c.table("activity_signups").update({
                "status": status,
                "eating": eating,
                "meal_choice": meal_choice,
            }).eq("id", sid).execute()
        else:
            return c.table("activity_signups").insert({
                "activiteit_id": activiteit_id,
                "username": username,
                "lid_id": lid_id,
                "status": status,
                "eating": eating,
                "meal_choice": meal_choice,
            }).execute()
    run_db(_write, what="signup upsert")

# ──────────────────────────────────────────────────────────────────────────────
# PAGINA'S
# ──────────────────────────────────────────────────────────────────────────────

def page_home():
    appbar("home")
    st.header("Welkom bij de Duikclub")
    st.write("Gebruik de navigatie links om te wisselen tussen Activiteiten, Duiken, Afrekening en Leden.")

def page_activiteiten():
    appbar("activiteiten")
    st.header("Kalender & Inschrijvingen")

    # ADMIN: activiteit toevoegen
    if current_role() == "admin":
        with st.expander("➕ Nieuwe activiteit"):
            c1, c2 = st.columns([2, 1])
            with c1:
                titel = st.text_input("Titel*")
                omschr = st.text_area("Omschrijving")
            with c2:
                datum = st.date_input("Datum*", value=datetime.date.today())
                # 👉 FIX: optioneel tijdveld zonder None aan st.time_input te geven
                add_time = st.checkbox("Tijd toevoegen", value=False, key="act_has_time")
                tijd = st.time_input("Tijd", value=datetime.time(19, 0), step=300, key="act_time") if add_time else None

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

            if st.button("Activiteit toevoegen", type="primary", key="act_add_btn"):
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
                            created_by=current_username() or current_email(),
                        )
                        st.success("Activiteit aangemaakt.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Mislukt: {e}")

    # Lijst met activiteiten
    df = activiteiten_list_df(upcoming=True)
    if df.empty:
        st.info("Nog geen activiteiten.")
        return

    df["datum"] = pd.to_datetime(df["datum"], errors="coerce")
    df = df.sort_values(["datum", "tijd"], ascending=[True, True])

    st.subheader("Aankomende activiteiten")
    for _, row in df.iterrows():
        titel = f"{row['titel']} — {row['datum'].strftime('%d/%m/%Y') if isinstance(row['datum'], pd.Timestamp) else row['datum']}"
        if row.get("tijd"):
            titel += f" · {row['tijd']}"
        with st.expander(titel, expanded=False):
            if row.get("locatie"):
                st.caption(f"📍 {row['locatie']}")
            if row.get("omschrijving"):
                st.write(row["omschrijving"]) 

            # inschrijven
            col1, col2 = st.columns([1, 2])
            with col1:
                status = st.radio("Kom je?", ["ja", "nee"], horizontal=True, index=0)
                eating = st.checkbox("Blijf je eten?", value=False)
                choice = None
            with col2:
                meal_options = row.get("meal_options") or []
                if isinstance(meal_options, list) and meal_options:
                    choice = st.selectbox("Kies maaltijd", ["— kies —"] + meal_options)

            if st.button("Opslaan", key=f"save_{row['id']}"):
                signup_upsert(
                    activiteit_id=row["id"],
                    username=current_username(),
                    lid_id=None,
                    status="yes" if status == "ja" else "no",
                    eating=bool(eating),
                    meal_choice=None if not choice or choice == "— kies —" else choice,
                )
                st.success("Je keuze is opgeslagen.")
                st.rerun()

# ──────────────────────────────────────────────────────────────────────────────
# DUIKEN
# ──────────────────────────────────────────────────────────────────────────────

def page_duiken():
    appbar("duiken")
    st.header("Duiken")

    with st.expander("➕ Duik toevoegen"):
        c1, c2, c3 = st.columns([1, 1, 1])
        with c1:
            datum = st.date_input("Datum", value=datetime.date.today())
            add_time = st.checkbox("Tijd toevoegen", value=False, key="d_has_time")
            tijd = st.time_input("Tijd", value=datetime.time(10, 0), step=300, key="d_time") if add_time else None
            plaats = st.selectbox("Plaats", ["— kies —"] + plaatsen_list(), index=0)
            new_plaats = st.text_input("Nieuwe plaats (indien niet in lijst)")
        with c2:
            water = st.selectbox("Water", ["Zoet", "Zout", "— onbekend —"], index=0)
            diepte = st.number_input("Diepte (m)", min_value=0.0, step=0.5, value=0.0)
            duur = st.number_input("Duur (min)", min_value=0, step=5, value=0)
            leidend = st.text_input("Leidend duiker")
        with c3:
            team = st.text_input("Team (comma-separated)")
            kosten = st.number_input("Kosten (€)", min_value=0.0, step=0.5, value=0.0)
            opmerkingen = st.text_area("Opmerkingen")

        if st.button("Duik opslaan", type="primary"):
            if new_plaats and new_plaats not in plaatsen_list():
                try:
                    plaats_add(new_plaats)
                    plaats_val = new_plaats
                except Exception as e:
                    st.error(f"Nieuwe plaats toevoegen mislukt: {e}")
                    plaats_val = None
            else:
                plaats_val = None if not plaats or plaats == "— kies —" else plaats

            payload = {
                "datum": datum.isoformat(),
                "tijd": tijd.isoformat() if tijd else None,
                "plaats": plaats_val,
                "water": None if water == "— onbekend —" else water,
                "diepte": diepte,
                "duur": duur,
                "leidend": (leidend or "").strip() or None,
                "team": (team or "").strip() or None,
                "opmerkingen": (opmerkingen or "").strip() or None,
                "kosten": kosten if kosten else 0.0,
                "created_by": current_username() or current_email(),
            }
            try:
                duik_add(payload)
                st.success("Duik opgeslagen.")
                st.rerun()
            except Exception as e:
                st.error(f"Opslaan mislukt: {e}")

    st.subheader("Overzicht duiken")
    df = duiken_list_df()
    if df.empty:
        st.info("Nog geen duiken ingevoerd.")
        return
    st.dataframe(df, use_container_width=True)

    st.subheader("Duik bewerken")
    ids = df["id"].tolist()
    if not ids:
        return
    sel = st.selectbox("Kies een duik", ids, format_func=lambda x: f"#{x}")
    row = df[df["id"] == sel].iloc[0]

    c1, c2, c3 = st.columns([1, 1, 1])
    with c1:
        datum2 = st.date_input("Datum", value=pd.to_datetime(row["datum"]).date() if row["datum"] else datetime.date.today(), key="edit_datum")
        add_time2 = st.checkbox("Tijd toevoegen", value=bool(row.get("tijd")), key="d2_has_time")
        default_time = None
        if row.get("tijd"):
            try:
                # probeer 'HH:MM:SS' te parsen
                hh, mm, *_ = str(row["tijd"]).split(":")
                default_time = datetime.time(int(hh), int(mm))
            except Exception:
                default_time = datetime.time(10, 0)
        tijd2 = st.time_input("Tijd", value=(default_time or datetime.time(10, 0)), step=300, key="d2_time") if add_time2 else None
        plaats2 = st.selectbox("Plaats", ["— kies —"] + plaatsen_list(), index=0, key="edit_plaats")
        new_plaats2 = st.text_input("Nieuwe plaats (indien niet in lijst)", key="edit_new_plaats")
    with c2:
        water2 = st.selectbox("Water", ["Zoet", "Zout", "— onbekend —"], index=0, key="edit_water")
        diepte2 = st.number_input("Diepte (m)", min_value=0.0, step=0.5, value=float(row.get("diepte") or 0.0), key="edit_diepte")
        duur2 = st.number_input("Duur (min)", min_value=0, step=5, value=int(row.get("duur") or 0), key="edit_duur")
        leidend2 = st.text_input("Leidend duiker", value=row.get("leidend") or "", key="edit_leidend")
    with c3:
        team2 = st.text_input("Team (comma-separated)", value=row.get("team") or "", key="edit_team")
        kosten2 = st.number_input("Kosten (€)", min_value=0.0, step=0.5, value=float(row.get("kosten") or 0.0), key="edit_kosten")
        opmerkingen2 = st.text_area("Opmerkingen", value=row.get("opmerkingen") or "", key="edit_opm")

    if st.button("Wijzigingen opslaan", key="edit_save", type="primary"):
        if new_plaats2 and new_plaats2 not in plaatsen_list():
            try:
                plaats_add(new_plaats2)
                plaats_val2 = new_plaats2
            except Exception as e:
                st.error(f"Nieuwe plaats toevoegen mislukt: {e}")
                plaats_val2 = None
        else:
            plaats_val2 = None if not plaats2 or plaats2 == "— kies —" else plaats2

        payload2 = {
            "datum": datum2.isoformat(),
            "tijd": tijd2.isoformat() if tijd2 else None,
            "plaats": plaats_val2,
            "water": None if water2 == "— onbekend —" else water2,
            "diepte": diepte2,
            "duur": duur2,
            "leidend": (leidend2 or "").strip() or None,
            "team": (team2 or "").strip() or None,
            "opmerkingen": (opmerkingen2 or "").strip() or None,
            "kosten": kosten2 if kosten2 else 0.0,
        }
        try:
            duik_update(sel, payload2)
            st.success("Duik bijgewerkt.")
            st.rerun()
        except Exception as e:
            st.error(f"Updaten mislukt: {e}")

# ──────────────────────────────────────────────────────────────────────────────
# AFREKENING
# ──────────────────────────────────────────────────────────────────────────────

def page_afrekening():
    appbar("afrekening")
    st.header("Afrekening & Kosten")

    with st.expander("➕ Kost toevoegen"):
        c1, c2 = st.columns([1, 2])
        with c1:
            datum = st.date_input("Datum", value=datetime.date.today())
            bedrag = st.number_input("Bedrag (€)", min_value=0.0, step=0.5, value=0.0)
            betaler = st.text_input("Betaler (naam/username)")
            status = st.selectbox("Status", ["open", "betaald"], index=0)
        with c2:
            oms = st.text_input("Omschrijving")
            verdeling = st.text_area("Verdeling (JSON of CSV met namen:bedrag)")

        if st.button("Kost opslaan", type="primary"):
            payload = {
                "datum": datum.isoformat(),
                "omschrijving": (oms or "").strip() or None,
                "bedrag": float(bedrag or 0.0),
                "betaler": (betaler or "").strip() or None,
                "verdeling": (verdeling or "").strip() or None,
                "nota_nr": None,
                "status": status,
            }
            try:
                afrekening_add(payload)
                st.success("Kost opgeslagen.")
                st.rerun()
            except Exception as e:
                st.error(f"Opslaan mislukt: {e}")

    st.subheader("Overzicht afrekening")
    df = afrekening_list_df()
    if df.empty:
        st.info("Nog geen kosten ingevoerd.")
        return
    st.dataframe(df, use_container_width=True)

    st.subheader("Kost bewerken")
    ids = df["id"].tolist()
    if not ids:
        return
    sel = st.selectbox("Kies een record", ids, format_func=lambda x: f"#{x}")
    row = df[df["id"] == sel].iloc[0]

    c1, c2 = st.columns([1, 2])
    with c1:
        datum2 = st.date_input("Datum", value=pd.to_datetime(row["datum"]).date() if row["datum"] else datetime.date.today(), key="afr_datum")
        bedrag2 = st.number_input("Bedrag (€)", min_value=0.0, step=0.5, value=float(row.get("bedrag") or 0.0), key="afr_bedrag")
        betaler2 = st.text_input("Betaler", value=row.get("betaler") or "", key="afr_betaler")
        status2 = st.selectbox("Status", ["open", "betaald"], index=0 if (row.get("status") or "open")=="open" else 1, key="afr_status")
    with c2:
        oms2 = st.text_input("Omschrijving", value=row.get("omschrijving") or "", key="afr_oms")
        verdeling2 = st.text_area("Verdeling", value=row.get("verdeling") or "", key="afr_verdeling")

    if st.button("Wijzigingen opslaan", key="afr_save", type="primary"):
        payload2 = {
            "datum": datum2.isoformat(),
            "omschrijving": (oms2 or "").strip() or None,
            "bedrag": float(bedrag2 or 0.0),
            "betaler": (betaler2 or "").strip() or None,
            "verdeling": (verdeling2 or "").strip() or None,
            "status": status2,
        }
        try:
            afrekening_update(sel, payload2)
            st.success("Record bijgewerkt.")
            st.rerun()
        except Exception as e:
            st.error(f"Updaten mislukt: {e}")

# ──────────────────────────────────────────────────────────────────────────────
# LEDEN
# ──────────────────────────────────────────────────────────────────────────────

def page_leden():
    appbar("leden")
    st.header("Ledenlijst")
    df = leden_list_df()
    if df.empty:
        st.info("Geen leden gevonden")
    else:
        st.dataframe(df, use_container_width=True)

# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

PAGES = {
    "Home": page_home,
    "Activiteiten": page_activiteiten,
    "Duiken": page_duiken,
    "Afrekening": page_afrekening,
    "Leden": page_leden,
}

def main():
    if not current_username():
        login_form()
        return
    choice = st.sidebar.radio("Navigatie", list(PAGES.keys()))
    PAGES[choice]()

if __name__ == "__main__":
    # Eenvoudige check op secrets
    if not SUPABASE_URL or not SUPABASE_KEY:
        st.warning("⚠️ SUPABASE_URL en/of SUPABASE_KEY ontbreken in secrets.toml — app draait in DEMO-modus.")
    main()
