# ── Activiteitenlijst (breed overzicht, tellers achteraan)
for i, (_, row) in enumerate(df.iterrows()):
    rid = row.get("id")
    sid = str(rid) if pd.notna(rid) and rid is not None else f"idx{i}"
    s = signups_get(row["id"])

    # totals
    if bool(row.get("enable_counts")):
        yes_adults = int(s.loc[s["status"]=="yes", "adults"].fillna(0).astype(int).sum()) if not s.empty else 0
        yes_children = int(s.loc[s["status"]=="yes", "children"].fillna(0).astype(int).sum()) if not s.empty else 0
        no_cnt = int((s["status"]=="no").sum()) if not s.empty else 0
        tellers_txt = f"<small><i>(V: {yes_adults} · K: {yes_children} · niet: {no_cnt})</i></small>"
    else:
        yes_cnt = int((s["status"]=="yes").sum()) if not s.empty else 0
        no_cnt = int((s["status"]=="no").sum()) if not s.empty else 0
        tellers_txt = f"<small><i>({yes_cnt} komen · {no_cnt} niet)</i></small>"

    # mijn status
    myrow = None
    if my_username:
        tmp = s.loc[s["username"] == my_username]
        if not tmp.empty: myrow = tmp
    if (myrow is None or myrow.empty) and my_lid_id:
        tmp = s.loc[s["lid_id"] == my_lid_id]
        if not tmp.empty: myrow = tmp
    my_status = (myrow.iloc[0]["status"] if (myrow is not None and not myrow.empty) else None)
    badge = "🟢" if my_status == "yes" else ("🔴" if my_status == "no" else "⚪")

    # regelkop
    datum_str = pd.to_datetime(row["datum"]).strftime("%d/%m/%Y")
    tijd_str = f" · {row['tijd']}" if row.get("tijd") else ""
    titel = f"{datum_str}{tijd_str} — {row['titel']}"
    loc_str = f" · 📍 {row['locatie']}" if row.get("locatie") else ""
    st.markdown(f"**{titel}{loc_str}**  {badge} &nbsp;&nbsp; {tellers_txt}", unsafe_allow_html=True)

    # expander met details + inschrijven
    with st.expander("Inschrijven / details", expanded=False):
        if row.get("omschrijving"):
            st.write(row["omschrijving"])

        # Lijsten (optioneel tonen aantallen per inschrijver)
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
                    extra = ""
                    if bool(row.get("enable_counts")):
                        va = int(ss.get("adults") or 0)
                        vk = int(ss.get("children") or 0)
                        extra = f" · (V:{va}, K:{vk})" if (va or vk) else ""
                    st.write(f"- {ss.get('username') or 'lid'}{meal}{extra}")

        with colB:
            st.markdown("**Niet komen:**")
            if notcoming.empty:
                st.caption("Nog niemand.")
            else:
                for _, ss in notcoming.iterrows():
                    st.write(f"- {ss.get('username') or 'lid'}")

        # Inschrijving (admin/user/member)
        if current_role() in {"admin", "user", "member"} and not is_readonly():
            st.divider()
            st.markdown("**Mijn inschrijving**")

            # vorige waarden ophalen
            prev_eating = False
            prev_meal = None
            prev_comment = ""
            prev_adults = 1
            prev_children = 0
            if myrow is not None and not myrow.empty:
                if pd.notna(myrow.iloc[0].get("eating")):
                    prev_eating = bool(myrow.iloc[0].get("eating"))
                pm = myrow.iloc[0].get("meal_choice")
                prev_meal = pm if isinstance(pm, str) and pm.strip() else None
                pc = myrow.iloc[0].get("comment")
                if isinstance(pc, str): prev_comment = pc
                pa = myrow.iloc[0].get("adults")
                if pd.notna(pa): prev_adults = int(pa)
                pk = myrow.iloc[0].get("children")
                if pd.notna(pk): prev_children = int(pk)

            init_index = 0 if my_status in (None, "yes") else 1
            status = st.radio("Status", ["Ik kom", "Ik kom niet"], horizontal=True, index=init_index, key=f"act_{sid}_status")

            # Opmerking: altijd zichtbaar (optioneel)
            comment_val = st.text_area("Opmerking (optioneel)", value=prev_comment, key=f"act_{sid}_comment")

            eating = None
            meal_choice = None
            adults_val = None
            children_val = None
            meal_opts = row.get("meal_options") or []

            if status == "Ik kom":
                eating = st.checkbox("Ik eet mee", value=prev_eating, key=f"act_{sid}_eat")
                if eating and meal_opts:
                    default_ix = 0
                    if prev_meal and prev_meal in meal_opts:
                        default_ix = meal_opts.index(prev_meal) + 1
                    mc = st.selectbox("Kies je maaltijd", ["— kies —"] + meal_opts, index=default_ix, key=f"act_{sid}_meal")
                    meal_choice = None if mc == "— kies —" else mc

                if bool(row.get("enable_counts")):
                    ca, cb = st.columns(2)
                    with ca:
                        adults_val = st.number_input("Volwassenen", min_value=0, max_value=50, step=1, value=max(1, prev_adults), key=f"act_{sid}_adults")
                    with cb:
                        children_val = st.number_input("Kinderen", min_value=0, max_value=50, step=1, value=max(0, prev_children), key=f"act_{sid}_children")

            if st.button("Bewaar mijn keuze", key=f"act_{sid}_save", type="primary"):
                try:
                    signup_upsert(
                        activiteit_id=row["id"],
                        username=my_username or None,
                        lid_id=my_lid_id or None,
                        status=("yes" if status == "Ik kom" else "no"),
                        eating=eating,
                        meal_choice=meal_choice,
                        comment=comment_val,
                        adults=adults_val,
                        children=children_val
                    )
                    st.success("Inschrijving bijgewerkt.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Opslaan mislukt: {e}")

        # Export / print
        st.markdown("---")
        st.markdown("**Afdrukvoorbeeld / export van inschrijvingen**")
        print_df = s[["username", "status", "eating", "meal_choice", "adults", "children", "comment", "signup_ts"]].copy()
        print_df = print_df.rename(columns={
            "username": "Gebruiker",
            "status": "Status",
            "eating": "Eet mee",
            "meal_choice": "Maaltijd",
            "adults": "Volw",
            "children": "Kind",
            "comment": "Opmerking",
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
            key=f"act_{sid}_csv"
        )
        st.caption("Tip: gebruik je browser-print (Ctrl/Cmd + P) op deze pagina voor papier/PDF.")
