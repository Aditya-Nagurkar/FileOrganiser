import os
import time
import requests
import hashlib
import streamlit as st


# Hardcoded VirusTotal API key (embed here). Replace with your actual key string.
VIRUSTOTAL_API_KEY: str = "484996da65bf5d8c55ea5f7b570425f751db8ae064b048f1849db9108f6cc708"  # e.g., "484996da65bf..."

def get_virustotal_api_key() -> str | None:
    # Prefer the embedded key. Fallback to env/secrets if empty.
    if VIRUSTOTAL_API_KEY:
        return VIRUSTOTAL_API_KEY
    try:
        key = st.secrets.get("VIRUSTOTAL_API_KEY")
    except Exception:
        key = None
    if not key:
        key = os.environ.get("VIRUSTOTAL_API_KEY")
    return key


def check_virus_total(file_path: str, api_key: str) -> str:
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return "⚠️ Infected" if (malicious > 0 or suspicious > 0) else "✅ Clean"
        return "❓ Unknown"
    except Exception as e:
        return f"Error: {e}"


def scan_files_for_viruses(file_list: list[dict], folder_path: str) -> list[str] | None:
    api_key = get_virustotal_api_key()
    if not api_key:
        st.error("VIRUSTOTAL_API_KEY is not set. Add it to Streamlit secrets or environment.")
        return None
    results: list[str] = []
    progress_bar = st.progress(0)
    total = len(file_list)
    for i, row in enumerate(file_list):
        file_path = os.path.join(folder_path, row["Location"], row["File Name"])
        results.append(check_virus_total(file_path, api_key))
        progress_bar.progress((i + 1) / total)
        time.sleep(1.5)
    return results
