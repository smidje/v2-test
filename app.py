# app.py — Duikers (voornaam/achternaam) + Afrekening met blokken & restbedragen
# ----------------------------------------------------------------------------
# Vereisten:
#   pip install streamlit pandas supabase==2.4.0 openpyxl python-dateutil
# Env vars:
#   SUPABASE_URL, SUPABASE_KEY
# Starten:
#   streamlit run app.py
# ----------------------------------------------------------------------------
# DB-schema (Supabase / Postgres) — voer dit uit in de SQL editor
# ----------------------------------------------------------------------------
# -- Tabel met duikers (nieuw of aanpassen)
# create table if not exists public.duikers (
#   id uuid primary key default gen_random_uuid(),
#   voornaam text,
#   achternaam text,
#   volledige_naam text generated always as ((coalesce(voornaam,'') || ' ' || coalesce(achternaam,''))::text) stored,
#   created_at timestamptz default now()
# );
# create index if not exists duikers_naam_idx on public.duikers (achternaam, voornaam);
# 
# -- Bestaande duiken-tabel laten zoals die is (bijv. met stringveld 'duiker').
# -- (Optioneel) Nieuwere, relationele aanpak:
# -- alter table public.duiken add column if not exists duiker_id uuid references public.duikers(id);
# -- je kunt dan de UI laten schrijven naar duiker_id i.p.v. stringnaam.
# 
# -- Historiek van afrekeningen
# create table if not exists public.afrekeningen (
#   id uuid primary key default gen_random_uuid(),
#   duiker_id uuid not null references public.duikers(id) on delete cascade,
#   periode_start date not null,
#   periode_end   date not null,
#   bedrag_per_duik numeric(10,2) not null,
#   blokgrootte numeric(10,2) not null,
#   aantal_duiken integer not null,
#   bruto_bedrag numeric(10,2) not null, -- aantal_duiken * bedrag_per_duik
#   rest_oud numeric(10,2) not null,      -- rest vorige periode
#   blokken integer not null,             -- aantal volledige blokken uitbetaald
#   uit_te_betalen numeric(10,2) not null,-- blokken * blokgrootte
#   rest_nieuw numeric(10,2) not null,    -- bruto_bedrag + rest_oud - uit_te_betalen
#   betaald_op timestamptz,               -- wanneer gemarkeerd als betaald
#   aangemaakt_op timestamptz default now()
# );
# create index if not exists afr_duiker_periode_idx on public.afrekeningen(duiker_id, periode_end desc);
# ----------------------------------------------------------------------------

import os
import io
import math
from datetime import date, datetime
from dateutil.relativedelta import relativedelta

import pandas as pd
import streamlit as st
from supabase import create_client, Client

# ─────────────────────────────────────────────────────────────────────────────
# Supabase client
# ─────────────────────────────────────────────────────────────────────────────
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
if not SUPABASE_URL or not SUPABASE_KEY:
    st.stop()

sb: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def run_db(fn, what: str = "query"):
    try:
        res = fn()
        if getattr(res, "error", None):
            raise RuntimeError(f"{what} error: {res.error}")
        return res
    except Exception as e:
        raise RuntimeError(f"DB {what} failed: {e}")


def fullname(vn: str | None, an: str | None) -> str:
    vn = (vn or "").strip()
    an = (an or "").strip()
    return (vn + (" " if vn and an else "") + an).strip()


def split_guess(full: str) -> tuple[str, str]:
    s = (full or "").strip()
    if not s:
        return "", ""
    parts = s.split()
    if len(parts) == 1:
        return "", parts[0]
    return parts[0], " ".join(parts[1:])


# ─────────────────────────────────────────────────────────────────────────────
# Data access
# ─────────────────────────────────────────────────────────────────────────────

def ensure_duiker(vn: str, an: str) -> str:
    """Zorgt dat een duiker bestaat; retourneert id (uuid)."""
    vn, an = (vn or "").strip(), (an or "").strip()
    # Zoek exact match op voornaam/achternaam
    res = run_db(lambda: sb.table("duikers").select("id").eq("voornaam", vn).eq("achternaam", an).limit(1).execute(),
                 "duikers select by name")
    rows = res.data or []
    if rows:
        return rows[0]["id"]
    # Anders insert
    ins = run_db(lambda: sb.table("duikers").insert({"voornaam": vn, "achternaam": an}).select("id").execute(),
                 "duikers insert")
    return ins.data[0]["id"]


def list_duikers_df() -> pd.DataFrame:
    res = run_db(lambda: sb.table("duikers").select("id, voornaam, achternaam, volledige_naam").order("achternaam").order("voornaam").execute(),
                 "duikers list")
    df = pd.DataFrame(res.data or [])
    if df.empty:
        df = pd.DataFrame(columns=["id","voornaam","achternaam","volledige_naam"]) 
    return df


def fetch_duiken_df() -> pd.DataFrame:
    # Verwachte kolommen in bestaande tabel: datum (date), plaats (text), duiker (text) of duiker_id (uuid), duikcode (optioneel)
    res = run_db(lambda: sb.table("duiken").select("*").execute(), "duiken select")
    df = pd.DataFrame(res.data or [])
    if df.empty:
        return pd.DataFrame(columns=["datum","plaats","duiker","duiker_id"])    
    # Normaliseer datum
    if "datum" in df.columns:
        df["Datum"] = pd.to_datetime(df["datum"]).dt.date
    else:
        df["Datum"] = pd.NaT
    # Resolve duikernaam indien duiker_id aanwezig
    if "duiker_id" in df.columns and df["duiker_id"].notna().any():
        ddf = list_duikers_df()
        df = df.merge(ddf[["id","volledige_naam"]], how="left", left_on="duiker_id", right_on="id")
        df["Duiker"] = df["volledige_naam"].fillna(df.get("duiker", ""))
    else:
        df["Duiker"] = df.get("duiker", "")
    df["Plaats"] = df.get("plaats", "")
    return df


def laatste_restbedrag(duiker_id: str) -> float:
    """Haalt het meest recente restbedrag uit afrekeningen voor deze duiker."""
    res = run_db(lambda: sb.table("afrekeningen").select("rest_nieuw, periode_end").eq("duiker_id", duiker_id).
                 order("periode_end", desc=True).limit(1).execute(), "afrekeningen last rest")
    rows = res.data or []
    if not rows:
        return 0.0
    return float(rows[0]["rest_nieuw"] or 0)


def insert_afrekening(row: dict):
    run_db(lambda: sb.table("afrekeningen").insert(row).execute(), "afrekeningen insert")

# ─────────────────────────────────────────────────────────────────────────────
# UI helpers
# ─────────────────────────────────────────────────────────────────────────────

def appbar(title: str):
    st.title(title)

# ─────────────────────────────────────────────────────────────────────────────
# Pagina: Beheer duikers (toevoegen, bekijken, verwijderen)
# ─────────────────────────────────────────────────────────────────────────────

def page_duikers():
    appbar("Beheer · Duikers")
    df = list_duikers_df()

    st.subheader("Duikers (overzicht)")
    if df.empty:
        st.info("Nog geen duikers.")
    else:
        view = df.rename(columns={"voornaam":"Voornaam","achternaam":"Achternaam","volledige_naam":"Weergave"})[
            ["Voornaam","Achternaam","Weergave"]
        ]
        st.dataframe(view, use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Nieuwe duiker toevoegen")
    c1,c2 = st.columns(2)
    with c1:
        vn = st.text_input("Voornaam", key="duiker_vn")
    with c2:
        an = st.text_input("Achternaam", key="duiker_an")
    if st.button("Toevoegen"):
        if not (vn or an):
            st.warning("Geef minstens één van voornaam of achternaam op.")
        else:
            try:
                _ = ensure_duiker(vn, an)
                st.success(f"Toegevoegd: {fullname(vn, an)}")
                st.rerun()
            except Exception as e:
                st.error(f"Toevoegen mislukt: {e}")

    st.divider()
    st.subheader("Duiker verwijderen")
    options = {row["volledige_naam"]: row["id"] for _, row in list_duikers_df().iterrows()}
    sel = st.multiselect("Kies duikers", list(options.keys()))
    if st.button("Verwijderen", type="secondary", disabled=len(sel)==0):
        try:
            ids = [options[name] for name in sel]
            for did in ids:
                run_db(lambda did=did: sb.table("duikers").delete().eq("id", did).execute(), "duiker delete")
            st.success(f"Verwijderd: {len(ids)}")
            st.rerun()
        except Exception as e:
            st.error(f"Verwijderen mislukt: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# Pagina: Afrekening (met blokken & restbedragen)
# ─────────────────────────────────────────────────────────────────────────────

def compute_afrekening_for_period(df_duiken: pd.DataFrame, start: date, end: date,
                                  bedrag_per_duik: float, blokgrootte: float,
                                  filter_plaats: str | None = None) -> pd.DataFrame:
    s = df_duiken[(df_duiken["Datum"]>=start) & (df_duiken["Datum"]<=end)].copy()
    if filter_plaats and filter_plaats != "Alle":
        s = s[s["Plaats"]==filter_plaats]
    if s.empty:
        return pd.DataFrame(columns=["duiker_id","Duiker","AantalDuiken","Bruto","RestOud","Totaal","Blokken","UitTeBetalen","RestNieuw"])

    # Koppel naar duiker_id als beschikbaar via naam
    dmap = list_duikers_df()
    # Map naam → id op basis van volledige_naam
    name_to_id = {r["volledige_naam"].strip(): r["id"] for _, r in dmap.iterrows()}

    grp = s.groupby("Duiker").size().reset_index(name="AantalDuiken")
    grp["Bruto"] = (grp["AantalDuiken"] * float(bedrag_per_duik)).round(2)

    # Verrijk met duiker_id + rest_oud
    grp["duiker_id"] = grp["Duiker"].map(name_to_id).fillna("")

    # Voor duikers die (nog) niet in duikers-table staan, geef tijdelijke id = ""
    rests = []
    for _, r in grp.iterrows():
        did = r["duiker_id"]
        rest_prev = laatste_restbedrag(did) if did else 0.0
        rests.append(rest_prev)
    grp["RestOud"] = [round(float(x),2) for x in rests]
    grp["Totaal"] = (grp["Bruto"] + grp["RestOud"]).round(2)

    # Bepaal blokken en uitbetaling
    def calc_blokken(total: float) -> tuple[int,float,float]:
        if blokgrootte <= 0:
            return 0, 0.0, round(total,2)
        n = math.floor(total / blokgrootte)
        uit = round(n * blokgrootte, 2)
        rest = round(total - uit, 2)
        return n, uit, rest

    b, u, r = [], [], []
    for t in grp["Totaal"].tolist():
        n, uit, rest = calc_blokken(float(t))
        b.append(n); u.append(uit); r.append(rest)
    grp["Blokken"] = b
    grp["UitTeBetalen"] = u
    grp["RestNieuw"] = r

    # Sorteer op Achternaam, Voornaam indien mogelijk
    # Voeg join met duikers om te sorteren
    if not dmap.empty:
        grp = grp.merge(dmap[["id","voornaam","achternaam"]], how="left", left_on="duiker_id", right_on="id")
        grp = grp.sort_values(["achternaam","voornaam","Duiker"], na_position="last")
        grp = grp.drop(columns=["id"])  # tijdelijke join kolom
    else:
        grp = grp.sort_values(["Duiker"])    

    return grp.reset_index(drop=True)


def page_afrekening():
    appbar("Afrekening")
    df = fetch_duiken_df()
    if df.empty:
        st.info("Nog geen duiken geregistreerd.")
        return

    min_d, max_d = df["Datum"].min(), df["Datum"].max()
    c1,c2,c3,c4 = st.columns(4)
    with c1:
        rng = st.date_input("Periode", (min_d, max_d), format="DD/MM/YYYY")
        start, end = rng if isinstance(rng, tuple) else (min_d, max_d)
    with c2:
        bedrag = st.number_input("Bedrag per duik (€)", min_value=0.0, step=0.5, value=5.0)
    with c3:
        plaats = st.selectbox("Plaats (optioneel)", ["Alle"] + sorted(df["Plaats"].dropna().unique().tolist()))
    with c4:
        blokgrootte = st.selectbox("Blokgrootte", [10.0, 30.0, 50.0], index=1)

    res = compute_afrekening_for_period(df, start, end, bedrag, blokgrootte, plaats)
    if res.empty:
        st.warning("Geen resultaten in de gekozen filters.")
        return

    # Toon tabel met kolommen in gewenste volgorde
    cols = [
        "Duiker","AantalDuiken","Bruto","RestOud","Totaal","Blokken","UitTeBetalen","RestNieuw"
    ]
    st.subheader("Overzicht per duiker")
    st.dataframe(res[cols], use_container_width=True, hide_index=True)

    total_uit = float(res["UitTeBetalen"].sum())
    total_rest = float(res["RestNieuw"].sum())
    cA,cB = st.columns(2)
    with cA:
        st.metric("Totaal uit te betalen", f"€ {total_uit:,.2f}".replace(",","X").replace(".",",").replace("X","."))
    with cB:
        st.metric("Nieuw totaal restbedrag", f"€ {total_rest:,.2f}".replace(",","X").replace(".",",").replace("X","."))

    st.divider()
    st.subheader("Historiek vastleggen / Markeer als betaald")
    st.caption("Selecteer één of meerdere duikers en registreer de afrekening. Dit creëert een historiek en bewaart het nieuwe restbedrag.")

    # Selectie en bevestiging
    res["select"] = False
    for i in range(len(res)):
        res.at[i, "select"] = st.checkbox(res.at[i, "Duiker"], key=f"sel_{i}")

    if st.button("Markeer geselecteerde als betaald"):
        try:
            sel = res[res["select"] == True]
            if sel.empty:
                st.warning("Geen duikers geselecteerd.")
            else:
                for _, r in sel.iterrows():
                    row = {
                        "duiker_id": r.get("duiker_id") or None,
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
                        "betaald_op": datetime.utcnow().isoformat()
                    }
                    insert_afrekening(row)
                st.success(f"Afrekening geregistreerd voor {len(sel)} duiker(s).")
                st.rerun()
        except Exception as e:
            st.error(f"Registratie mislukt: {e}")

    st.divider()
    st.subheader("Export (Excel)")
    # Excel met 3 bladen: Overzicht, Detail duiken, Afrekeningen historiek (laatste 12 maanden)
    out = io.BytesIO()
    with pd.ExcelWriter(out, engine="openpyxl") as w:
        res[cols].to_excel(w, index=False, sheet_name="Afrekening")
        # Detail binnen periode
        det = df[(df["Datum"]>=start) & (df["Datum"]<=end)].copy()
        det = det.sort_values(["Datum","Plaats","Duiker"]).reset_index(drop=True)
        det.to_excel(w, index=False, sheet_name="DetailDuiken")
        # Historiek (recent)
        afr = run_db(lambda: sb.table("afrekeningen").select("*, duiker_id").gte("periode_end", (date.today()-relativedelta(months=12)).isoformat()).execute(),
                     "afrekeningen recent").data or []
        afr_df = pd.DataFrame(afr)
        if not afr_df.empty:
            # Join met namen
            ddf = list_duikers_df()
            afr_df = afr_df.merge(ddf[["id","voornaam","achternaam","volledige_naam"]], how="left", left_on="duiker_id", right_on="id")
            afr_df = afr_df.drop(columns=["id_y"]) if "id_y" in afr_df.columns else afr_df
            afr_df.rename(columns={"id_x":"id"}, inplace=True)
            # Sorteer
            afr_df = afr_df.sort_values(["periode_end","achternaam","voornaam"], ascending=[False,True,True])
        else:
            afr_df = pd.DataFrame(columns=["id","duiker_id","periode_start","periode_end","uit_te_betalen","rest_nieuw"])        
        afr_df.to_excel(w, index=False, sheet_name="Historiek")

    st.download_button(
        "⬇️ Download Afrekening.xlsx",
        data=out.getvalue(),
        file_name=f"Afrekening_{start}_{end}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

# ─────────────────────────────────────────────────────────────────────────────
# Pagina: Dashboard (optioneel eenvoudig overzicht)
# ─────────────────────────────────────────────────────────────────────────────

def page_dashboard():
    appbar("Dashboard")
    df = fetch_duiken_df()
    if df.empty:
        st.info("Nog geen duiken.")
        return
    st.metric("Totaal duiken", len(df))
    st.write("Laatste 10 duiken:")
    last = df.sort_values("Datum", ascending=False).head(10)[["Datum","Plaats","Duiker"]]
    st.dataframe(last, use_container_width=True, hide_index=True)

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    st.set_page_config(page_title="Duikclub", layout="wide")
    tabs = st.tabs(["Dashboard", "Afrekening", "Beheer duikers"])    
    with tabs[0]:
        page_dashboard()
    with tabs[1]:
        page_afrekening()
    with tabs[2]:
        page_duikers()

if __name__ == "__main__":
    main()
