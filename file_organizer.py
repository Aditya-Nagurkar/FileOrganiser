import os
import streamlit as st
import pandas as pd
from pathlib import Path
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go

# Ensure project root is on sys.path so `src/...` imports resolve locally and in Streamlit Cloud
import sys
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import modularized helpers
from src.utils.directory_utils import (
    get_available_drives as get_drives,
    validate_directory_access,
    get_directory_contents,
)
from src.utils.file_utils import (
    get_file_category,
    get_file_size_category,
    get_date_category,
    calculate_file_hash,
    detect_suspicious_file,
    get_file_icon,
    create_archive,
    find_duplicates,
    get_file_preview,
)
from src.security.virus_scanner import get_virustotal_api_key
from src.ui.organization import render_organization
from src.ui.bulk_ops import render_bulk_ops
from src.ui.analysis import render_analysis
from src.ui.security import render_security

st.set_page_config(page_title="📁 File Organizer & Virus Scanner", layout="wide")

# Custom CSS for better chart styling
st.markdown("""
<style>
    /* Chart styling */
    .stBarChart {
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    /* Metric cards styling */
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 0.5rem 0;
    }
    
    /* Section headers */
    .section-header {
        background: linear-gradient(90deg, #667eea, #764ba2);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: bold;
        margin: 1rem 0;
    }
    
    /* Data table styling */
    .dataframe {
        border-radius: 10px;
        overflow: hidden;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    /* Button styling */
    .stButton > button {
        border-radius: 20px;
        border: none;
        background: linear-gradient(45deg, #667eea, #764ba2);
        color: white;
        font-weight: bold;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }
</style>
""", unsafe_allow_html=True)

st.title("🗃️ File Organizer & Virus Scanner")

# Sidebar for additional options
with st.sidebar:
    st.header("⚙️ Settings")
    
    # File size limits
    max_preview_size = st.slider("Max Preview Size (MB)", 1, 50, 10)
    
    # Organization preferences
    st.subheader("📁 Organization Preferences")
    auto_create_folders = st.checkbox("Auto-create folders", value=True)
    preserve_structure = st.checkbox("Preserve folder structure", value=False)
    
    # Security settings
    st.subheader("🛡️ Security Settings")
    scan_large_files = st.checkbox("Scan large files (>100MB)", value=False)
    quarantine_suspicious = st.checkbox("Auto-quarantine suspicious files", value=False)

available_drives = get_drives()


# helper functions are imported from src.utils and src.security modules

# Add custom path option
st.subheader("📁 Select Directory")

selected_drive = st.selectbox("💽 Select from common directories:", options=available_drives)

if selected_drive:
    BASE_DIR = Path(selected_drive)

    try:
        # Check if directory exists and is accessible
        if not BASE_DIR.exists():
            st.error(f"🚫 Directory '{selected_drive}' does not exist.")
            st.stop()
        
        if not BASE_DIR.is_dir():
            st.error(f"🚫 '{selected_drive}' is not a directory.")
            st.stop()
            
        if not os.access(selected_drive, os.R_OK):
            st.error(f"🚫 No read permission for '{selected_drive}'.")
            st.stop()

        folder_options = [
            (f"📁 Root of {selected_drive}", BASE_DIR)
        ]
        
        # Try to list subdirectories
        try:
            subdirs = [
                (f"📂 {f.name}", f)
                for f in BASE_DIR.iterdir()
                if f.is_dir() and os.access(f, os.R_OK)
            ]
            folder_options.extend(subdirs)
        except PermissionError:
            st.warning(f"⚠️ Limited access to subdirectories in '{selected_drive}'.")
            
    except Exception as e:
        st.error(f"🚫 Error accessing '{selected_drive}': {str(e)}")
        st.stop()

    selected_label = st.selectbox(
        "📂 Select a folder to manage:",
        options=[label for label, _ in folder_options]
    )

    selected_folder = dict(folder_options)[selected_label]

    # Custom path option after folder selection
    st.markdown("---")
    custom_path = st.text_input("📝 Enter custom path:", placeholder="/path/to/your/directory")

    if custom_path and os.path.exists(custom_path) and os.path.isdir(custom_path):
        selected_folder = Path(custom_path)
        st.success(f"✅ Using custom path: {custom_path}")
    elif custom_path:
        st.error(f"❌ Path '{custom_path}' does not exist or is not a directory")
        st.stop()

    if selected_folder:
        folder = str(selected_folder)

        # Organization section
        render_organization(folder)
        
        # Bulk operations section
        render_bulk_ops(folder)

        # Analysis + Security sections
        df, _ = render_analysis(folder)
        if df is not None:
            render_security(folder, df)
        else:
            st.info("📂 No files found in this folder.")
