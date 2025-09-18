import streamlit as st
import pandas as pd
import datetime
from datetime import datetime as dt
from supabase import create_client, Client
import io
import math
import json

st.set_page_config(page_title="ANWW Afrekening v2 (TEST)", layout="wide")

# ──────────────────────────────
# Supabase client
# ──────────────────────────────
@st.cache_resource
def get_client() -> Client:
    url = st.secrets["supabase"]["url"]
    key = st.secrets["supabase"]["anon_key"]
    return create_client(url, key)

sb = get_client()

# ──────────────────────────────
# Thema (pakt jouw [theme] uit secrets automatisch)
# ──────────────────────────────
def _merge_theme(defaults: dict, overrides: dict | None) -> dict:
    if not overrides:
        return defaults
    d = defaults.copy()
    d.update({k: v for k, v in overrides.items() if v})
    return d

def inject_theme():
    defaults = {
        "bg": "#f7f9fc", "surface": "#f0f4ff", "card": "#ffffff", "border": "#e5e7eb",
        "text": "#0f172a", "muted": "#475569", "primary": "#2563eb", "primary_contrast": "#ffffff",
        "accent": "#38bdf8", "success": "#16a34a", "warning": "#f59e0b", "error": "#ef4444",
    }
    theme = _merge_theme(defaults, st.secrets.get("theme"))
    css = f"""
    :root {{
      --bg:{theme['bg']}; --surface:{theme['surface']}; --card:{theme['card']}; --border:{theme['border']};
      --text:{theme['text']}; --muted:{theme['muted']}; --primary:{theme['primary']};
      --primary-contrast:{theme['primary_contrast']}; --accent:{theme['accent']};
      --success:{theme['success']}; --warning:{theme['warning']}; --error:{theme['error']};
    }}
    .stApp{{background: radial-gradient(1200px 800px at 20% 10%, var(--surface), var(--bg) 60%); color: var(--text);}}
    .badge{{border:1px solid var(--border); background:var(--card); color:var(--text); border-radius:999px; padding:4px 10px;}}
    """
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)

inject_theme()

st.title("ANWW Afrekening v2 (TEST)")

# ──────────────────────────────
# DB helpers
# ──────────────────────────────
def list_duikers_v2() -> pd.DataFrame:
    res = sb.table("duikers_v2").select("*").order("achternaam").order("voornaam").execute()
    return pd.DataFrame(res.data or [])

def insert_duiker_v2(voornaam: str, achternaam: str):
    sb.table("duikers_v2").insert({"voornaam": voornaam.strip(), "achternaam": achternaam.strip()}).execute()

def fetch_duiken(start: datetime.date = None, end: datetime.date = None) -> pd.DataFrame:
    q = sb.table("duiken").select("*")
    if start:
        q = q.gte("datum", start.isoformat())
    if end:
        q = q.lte("datum", end.isoformat())
    res = q.execute()
    df = pd.DataFrame(res.data or [])
    if not df.empty:
        df["Datum"] = pd.to_datetime(df["datum"]).dt.date
        df["Duiker"] = df["duiker"]
    return df

def get_saldo_map() -> dict[str, float]:
    res = sb.table("afrekening_saldo").select("*").execute()
    rows = res.data or []
    return {r["duiker_volledige_naam"]: float(r["saldo"]) for r in rows}

def upsert_saldo(naam: str, saldo: float):
    sb.table("afrekening_saldo").upsert({
        "duiker_volledige_naam": naam,
        "saldo": round(float(saldo), 2),
        "updated_at": dt.utcnow().isoformat()
    }).execute()

def insert_historiek(row: dict):
    sb.table("afrekening_historiek").insert(row).execute()

# ──────────────────────────────
# Rekenkern
# ──────────────────────────────
def greedy_blokken(total: float, blokken=(50, 30, 10)) -> tuple[float, dict]:
    """Neem zo veel mogelijk grote blokken (50, dan 30, dan 10) zonder total te overschrijden."""
    remaining = round(total, 2)
    used = {}
    settled = 0.0
    for b in sorted(blokken, reverse=True):
        n = int(math.floor(remaining / b))
        used[str(b)] = n
        settled += n * b
        remaining = round(total - settled, 2)
    return round(settled, 2), used

def compute_afrekening(df_duiken: pd.DataFrame, bedrag_per_duik: float,
                       rest_prev: dict[str, float],
                       blokken=(10, 30, 50)) -> pd.DataFrame:
    if df_duiken.empty:
        return pd.DataFrame(columns=[
            "Duiker", "aantal_duiken", "bedrag_huidig", "rest_in", "totaal",
            "settled_blokken", "rest_out", "blokken_json"
        ])

    per = df_duiken.groupby("Duiker").size().reset_index(name="aantal_duiken")
    per["bedrag_huidig"] = (per["aantal_duiken"] * float(bedrag_per_duik)).round(2)
    per["rest_in"] = per["Duiker"].map(lambda n: round(float(rest_prev.get(n, 0.0)), 2))
    per["totaal"] = (per["bedrag_huidig"] + per["rest_in"]).round(2)

    rows = []
    for _, r in per.iterrows():
        settled, used = greedy_blokken(float(r["totaal"]), blokken=blokken)
        rest_out = round(float(r["totaal"]) - settled, 2)
        rows.append({
            "DaN": r["Duiker"],
            "Duiker": r["Duiker"],
            "aantal_duiken": int(r["aantal_duiken"]),
            "bedrag_huidig": float(r["bedrag_huidig"]),
            "rest_in": float(r["rest_in"]),
            "totaal": float(r["totaal"]),
            "settled_blokken": settled,
            "rest_out": rest_out,
            "blokken_json": json.dumps(used),
        })
    out = pd.DataFrame(rows)
    out = out.sort_values(["DaN"]).drop(columns=["DaN"])
    return out

# ──────────────────────────────
# UI
# ──────────────────────────────
tabs = st.tabs(["Duikers v2", "Afrekening v2", "Historiek"])

with tabs[0]:
    st.subheader("Duikers v2 — voornaam & achternaam (TEST)")
    d = list_duikers_v2()
    # Fix: 'volledige_naam' may not exist yet, so add it if missing
    if "volledige_naam" not in d.columns:
        d["volledige_naam"] = d["voornaam"].astype(str) + " " + d["achternaam"].astype(str)
    st.dataframe(d[["voornaam", "achternaam", "volledige_naam"]], use_container_width=True, hide_index=True)

    st.markdown("**Nieuwe duiker**")
    c1, c2 = st.columns(2)
    with c1:
        v = st.text_input("Voornaam")
    with c2:
        a = st.text_input("Achternaam")
    if st.button("Toevoegen (v2)"):
        if v.strip() and a.strip():
            try:
                insert_duiker_v2(v, a)
                st.success(f"Toegevoegd: {v} {a}")
                st.experimental_rerun()
            except Exception as e:
                st.error(f"Mislukt: {e}")
        else:
            st.warning("Beide velden invullen aub.")

with tabs[1]:
    st.subheader("Afrekening v2 met blokken & restbedragen (TEST)")

    df2 = list_duikers_v2()
    # Fix: 'volledige_naam' may not exist yet, so add it if missing
    if "volledige_naam" not in df2.columns:
        df2["volledige_naam"] = df2["voornaam"].astype(str) + " " + df2["achternaam"].astype(str)
    df2_names = df2["volledige_naam"].tolist()

    c1, c2, c3 = st.columns(3)
    with c1:
        today = datetime.date.today()
        default_start = today.replace(day=1)
        rng = st.date_input("Periode", (default_start, today), format="DD/MM/YYYY")
    with c2:
        bedrag = st.number_input("Bedrag per duik (€)", min_value=0.0, step=0.5, value=5.0)
    with c3:
        blokken_sel = st.multiselect("Blokken (€)", options=[10, 30, 50], default=[10, 30, 50], help="Worden greedy toegepast (50→30→10).")

    # Fix: st.date_input returns a tuple (start, end) or a single date
    if isinstance(rng, (tuple, list)) and len(rng) == 2:
        start, end = rng
    else:
        start, end = default_start, today

    all_duiken = fetch_duiken(start, end)

    # Alleen duikers die in v2 bestaan tonen (optioneel filter)
    if not all_duiken.empty:
        all_duiken = all_duiken[all_duiken["Duiker"].isin(df2_names)]

    saldo_map = get_saldo_map()

    # Handmatige correctie
    base_rest = pd.DataFrame({"Duiker": df2_names, "rest_in_db": [saldo_map.get(n, 0.0) for n in df2_names]})
    edited = st.data_editor(
        base_rest.rename(columns={"rest_in_db": "rest_in_override"}),
        use_container_width=True, hide_index=True,
        column_config={"rest_in_override": st.column_config.NumberColumn(format="%.2f")}
    )
    rest_in = {row["Duiker"]: (row["rest_in_override"] if row["rest_in_override"] is not None else saldo_map.get(row["Duiker"], 0.0))
               for _, row in edited.iterrows()}

    st.markdown("**Voorlopige berekening**")
    calc = compute_afrekening(all_duiken, bedrag_per_duik=bedrag, rest_prev=rest_in, blokken=tuple(sorted(blokken_sel)))
    if calc.empty:
        st.info("Geen data in deze periode of (nog) geen duikers v2.")
    else:
        view = calc.copy()
        for c in ["bedrag_huidig", "rest_in", "totaal", "settled_blokken", "rest_out"]:
            view[c] = view[c].map(lambda x: f"€ {x:,.2f}".replace(",", "X").replace(".", ",").replace("X", "."))
        st.dataframe(view[["Duiker", "aantal_duiken", "bedrag_huidig", "rest_in", "totaal", "settled_blokken", "rest_out", "blokken_json"]],
                     use_container_width=True, hide_index=True)

        total_settled = calc["settled_blokken"].sum().round(2)
        total_rest = calc["rest_out"].sum().round(2)
        st.metric("Totaal afgerekend (blokken)", f"€ {total_settled:,.2f}".replace(",", "X").replace(".", ",").replace("X", "."))
        st.metric("Som resterend", f"€ {total_rest:,.2f}".replace(",", "X").replace(".", ",").replace("X", "."))

        out = io.BytesIO()
        with pd.ExcelWriter(out, engine="openpyxl") as w:
            calc.to_excel(w, index=False, sheet_name="Afrekening_v2_raw")
            view.to_excel(w, index=False, sheet_name="Afrekening_v2_weergave")
        st.download_button("⬇️ Download Afrekening (Excel)", data=out.getvalue(),
            file_name="Afrekening_v2.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

        st.divider()
        if st.button("✅ Markeer als betaald & opslaan (historiek + saldo bijwerken)"):
            try:
                for _, r in calc.iterrows():
                    insert_historiek({
                        "duiker_volledige_naam": r["Duiker"],
                        "periode_start": start.isoformat(),
                        "periode_end": end.isoformat(),
                        "bedrag_per_duik": float(bedrag),
                        "aantal_duiken": int(r["aantal_duiken"]),
                        "bedrag_huidig": float(r["bedrag_huidig"]),
                        "rest_in": float(r["rest_in"]),
                        "settled_blokken": float(r["settled_blokken"]),
                        "rest_out": float(r["rest_out"]),
                        "blokken": json.dumps(json.loads(r["blokken_json"])),
                        "betaald": True,
                        "betaald_op": dt.utcnow().isoformat(),
                    })
                    upsert_saldo(r["Duiker"], float(r["rest_out"]))
                st.success("Afrekening opgeslagen en gemarkeerd als betaald. Saldi bijgewerkt ✅")
            except Exception as e:
                st.error(f"Opslaan mislukt: {e}")

with tabs[2]:
    st.subheader("Historiek (TEST)")
    q = sb.table("afrekening_historiek").select("*").order("created_at", desc=True).limit(200).execute()
    hist = pd.DataFrame(q.data or [])
    if hist.empty:
        st.info("Nog geen historiek.")
    else:
        show = hist.copy()
        money_cols = ["bedrag_per_duik", "bedrag_huidig", "rest_in", "settled_blokken", "rest_out"]
        for c in money_cols:
            show[c] = show[c].astype(float).map(lambda x: f"€ {x:,.2f}".replace(",", "X").replace(".", ",").replace("X", "."))
        st.dataframe(
            show[["duiker_volledige_naam", "periode_start", "periode_end", "bedrag_per_duik", "aantal_duiken",
                  "bedrag_huidig", "rest_in", "settled_blokken", "rest_out", "betaald", "betaald_op", "blokken", "created_at"]],
            use_container_width=True, hide_index=True
        )
