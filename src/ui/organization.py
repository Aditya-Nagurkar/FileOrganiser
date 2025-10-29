import os
import shutil
from datetime import datetime
import streamlit as st

from src.utils.file_utils import (
    get_file_category,
    get_file_size_category,
)
from src.utils.file_utils import create_archive


def render_organization(folder: str) -> None:
    st.markdown("---")
    st.subheader("🗂️ File Organization Options")

    st.markdown(
        """
        <style>
        .org-button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 12px;
            color: white;
            padding: 1rem;
            font-weight: bold;
            font-size: 14px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .org-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.2);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    col1, col2, col3 = st.columns(3, gap="medium")

    with col1:
        if st.button("📦 Organize by Extension", width='stretch', key="ext_btn"):
            moved_files = 0
            for file in os.listdir(folder):
                file_path = os.path.join(folder, file)
                try:
                    if os.path.isfile(file_path):
                        ext = os.path.splitext(file)[1].lower()
                        target_folder = os.path.join(folder, ext[1:] if ext else "no_extension")
                        os.makedirs(target_folder, exist_ok=True)
                        shutil.move(file_path, os.path.join(target_folder, file))
                        moved_files += 1
                except (FileNotFoundError, PermissionError, OSError):
                    continue
            st.success(f"✅ Organized {moved_files} file(s) by extension!")

    with col2:
        if st.button("🏷️ Organize by Type", width='stretch', key="type_btn"):
            moved_files = 0
            for file in os.listdir(folder):
                file_path = os.path.join(folder, file)
                try:
                    if os.path.isfile(file_path):
                        category = get_file_category(file_path)
                        target_folder = os.path.join(folder, category)
                        os.makedirs(target_folder, exist_ok=True)
                        shutil.move(file_path, os.path.join(target_folder, file))
                        moved_files += 1
                except (FileNotFoundError, PermissionError, OSError):
                    continue
            st.success(f"✅ Organized {moved_files} file(s) by type!")

    with col3:
        if st.button("📅 Organize by Date", width='stretch', key="date_btn"):
            moved_files = 0
            for file in os.listdir(folder):
                file_path = os.path.join(folder, file)
                try:
                    if os.path.isfile(file_path):
                        mtime = os.path.getmtime(file_path)
                        date_cat = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d")
                        target_folder = os.path.join(folder, date_cat)
                        os.makedirs(target_folder, exist_ok=True)
                        shutil.move(file_path, os.path.join(target_folder, file))
                        moved_files += 1
                except (FileNotFoundError, PermissionError, OSError):
                    continue
            st.success(f"✅ Organized {moved_files} file(s) by date!")

    col4, col5, col6 = st.columns(3, gap="medium")

    with col4:
        if st.button("📏 Organize by Size", width='stretch', key="size_btn"):
            moved_files = 0
            for file in os.listdir(folder):
                file_path = os.path.join(folder, file)
                try:
                    if os.path.isfile(file_path):
                        size = os.path.getsize(file_path)
                        size_cat = get_file_size_category(size)
                        target_folder = os.path.join(folder, f"Size_{size_cat}")
                        os.makedirs(target_folder, exist_ok=True)
                        shutil.move(file_path, os.path.join(target_folder, file))
                        moved_files += 1
                except (FileNotFoundError, PermissionError, OSError):
                    continue
            st.success(f"✅ Organized {moved_files} file(s) by size!")

    with col5:
        if st.button("🔍 Find Duplicates", width='stretch', key="dup_btn_info"):
            st.info("Use the Analyze Duplicates button in the analysis section below.")

    with col6:
        if st.button("📦 Create Archive", width='stretch', key="arch_btn"):
            all_files = []
            for root, _, files in os.walk(folder):
                for f in files:
                    all_files.append(os.path.join(root, f))
            if all_files:
                archive_path = os.path.join(folder, f"archive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
                if create_archive(all_files, archive_path):
                    st.success(f"✅ Created archive: {os.path.basename(archive_path)}")
                else:
                    st.error("❌ Failed to create archive")
            else:
                st.info("No files to archive")
