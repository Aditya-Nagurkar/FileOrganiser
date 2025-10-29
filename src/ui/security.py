import os
import time
import streamlit as st

from src.security.virus_scanner import get_virustotal_api_key, check_virus_total


def render_security(folder: str, df) -> None:
    st.markdown("---")
    st.subheader("👾 Virus Scan")

    api_key = get_virustotal_api_key()
    if not api_key:
        st.error("VIRUSTOTAL_API_KEY is not set. Add it to Streamlit secrets or environment.")
        return

    if st.button("🚨 Scan Files for Viruses"):
        st.write("🔍 Scanning files... please wait...")
        results = []
        progress_bar = st.progress(0)
        total = len(df)
        for i, (_, row) in enumerate(df.iterrows()):
            file_path = os.path.join(folder, row["Location"], row["File Name"])
            status = check_virus_total(file_path, api_key)
            results.append(status)
            progress_bar.progress((i + 1) / total)
            time.sleep(1.5)
        df["Virus Check"] = results
        st.success("✅ Virus scan completed!")
        st.dataframe(df, width='stretch')
