import os
import streamlit as st


def render_bulk_ops(folder: str) -> None:
    st.markdown("---")
    st.subheader("🔧 Bulk Operations")

    st.write("**📝 Batch File Renaming**")
    rename_pattern = st.text_input(
        "Rename pattern:", placeholder="file_{i:03d} (will create file_001, file_002, etc.)"
    )
    col_rename1, _ = st.columns([3, 1])
    with col_rename1:
        if st.button("🔄 Rename Files", width='stretch') and rename_pattern:
            renamed_count = 0
            for i, file in enumerate(os.listdir(folder)):
                file_path = os.path.join(folder, file)
                if os.path.isfile(file_path):
                    try:
                        ext = os.path.splitext(file)[1]
                        new_name = rename_pattern.format(i=i + 1) + ext
                        new_path = os.path.join(folder, new_name)
                        os.rename(file_path, new_path)
                        renamed_count += 1
                    except Exception:
                        continue
            st.success(f"✅ Renamed {renamed_count} files!")

    st.markdown("---")

    st.write("**🗑️ Other Bulk Operations**")
    col_bulk1, col_bulk2 = st.columns(2)

    with col_bulk1:
        if st.button("🗑️ Delete Empty Folders", width='stretch'):
            deleted_count = 0
            for root, dirs, _ in os.walk(folder, topdown=False):
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    try:
                        if not os.listdir(dir_path):  # Empty directory
                            os.rmdir(dir_path)
                            deleted_count += 1
                    except Exception:
                        continue
            st.success(f"✅ Deleted {deleted_count} empty folders!")

    with col_bulk2:
        if st.button("📏 Sort by Size", width='stretch'):
            files_with_size = []
            for file in os.listdir(folder):
                file_path = os.path.join(folder, file)
                if os.path.isfile(file_path):
                    files_with_size.append((file, os.path.getsize(file_path)))
            files_with_size.sort(key=lambda x: x[1], reverse=True)
            for i, (file, size) in enumerate(files_with_size):
                try:
                    ext = os.path.splitext(file)[1]
                    new_name = f"file_{i + 1:03d}_{size // 1024}KB{ext}"
                    old_path = os.path.join(folder, file)
                    new_path = os.path.join(folder, new_name)
                    os.rename(old_path, new_path)
                except Exception:
                    continue
            st.success("✅ Files sorted by size!")
