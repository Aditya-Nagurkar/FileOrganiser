import os
import pandas as pd
import streamlit as st
import plotly.express as px
from datetime import datetime

from src.utils.file_utils import (
    get_file_icon,
    get_file_size_category,
    get_date_category,
    get_file_category,
    calculate_file_hash,
    detect_suspicious_file,
    get_file_preview,
    find_duplicates,
)


def render_analysis(folder: str):
    st.markdown("---")
    st.subheader("📊 File Analysis & Statistics")

    search_term = st.text_input("🔍 Search files:", placeholder="Enter filename, extension, or content...")

    file_list = []
    all_files = []

    for root, _, files in os.walk(folder):
        for file in files:
            try:
                file_path = os.path.join(root, file)
                stats = os.stat(file_path)
                file_info = {
                    "Icon": get_file_icon(os.path.splitext(file)[1]),
                    "File Name": file,
                    "Size (KB)": round(stats.st_size / 1024, 2),
                    "Size Category": get_file_size_category(stats.st_size),
                    "Last Modified": datetime.fromtimestamp(stats.st_mtime),
                    "Date Category": get_date_category(file_path),
                    "Extension": os.path.splitext(file)[1].lower(),
                    "File Type": get_file_category(file_path),
                    "Location": os.path.relpath(root, folder),
                    "Full Path": file_path,
                    "Hash": calculate_file_hash(file_path),
                    "Suspicious": detect_suspicious_file(file_path),
                    "Permissions": oct(stats.st_mode)[-3:],
                    "Preview": get_file_preview(file_path) if os.path.getsize(file_path) < 10 * 1024 * 1024 else "File too large for preview",
                }
                if search_term:
                    s = search_term.lower()
                    if s in file.lower() or s in file_info["Extension"] or s in file_info["File Type"].lower():
                        file_list.append(file_info)
                else:
                    file_list.append(file_info)
                all_files.append(file_path)
            except (FileNotFoundError, PermissionError, OSError):
                continue

    if not file_list:
        return None, []

    df = pd.DataFrame(file_list)

    st.subheader("📄 Files in Folder")
    total_size = df["Size (KB)"].sum()
    st.metric("Total Files", len(df))
    st.metric("Total Size", f"{total_size:.2f} KB")

    st.subheader("📊 File Type Distribution")
    type_counts = df["File Type"].value_counts()
    type_df = pd.DataFrame(
        {
            "File Type": type_counts.index,
            "Count": type_counts.values,
            "Percentage": (type_counts.values / type_counts.sum() * 100).round(1),
        }
    )
    col1, col2 = st.columns([2, 1])
    with col1:
        fig = px.bar(
            x=type_counts.index,
            y=type_counts.values,
            title="File Type Distribution",
            labels={"x": "File Type", "y": "Number of Files"},
            color=type_counts.values,
            color_continuous_scale="viridis",
            height=400,
        )
        st.plotly_chart(fig, config={"responsive": True})
    with col2:
        st.dataframe(type_df, width='stretch')

    st.subheader("📏 File Size Distribution")
    size_counts = df["Size Category"].value_counts()
    col1, col2 = st.columns([2, 1])
    with col1:
        fig = px.pie(
            values=size_counts.values,
            names=size_counts.index,
            title="File Size Distribution",
            color_discrete_sequence=px.colors.qualitative.Set3,
            height=400,
        )
        st.plotly_chart(fig, config={"responsive": True})
    with col2:
        total_size_mb = df["Size (KB)"].sum() / 1024
        avg_size_kb = df["Size (KB)"].mean()
        largest_file = df.loc[df["Size (KB)"].idxmax(), "File Name"]
        largest_size = df["Size (KB)"].max()
        st.metric("Total Size", f"{total_size_mb:.1f} MB")
        st.metric("Average Size", f"{avg_size_kb:.1f} KB")
        st.metric("Largest File", f"{largest_size:.1f} KB")
        st.caption(f"Largest: {largest_file}")

    st.subheader("📅 File Age Distribution")
    date_counts = df["Date Category"].value_counts()
    date_order = ["Today", "Yesterday", "This Week", "This Month", "Older", "Unknown"]
    ordered_counts = {d: date_counts.get(d, 0) for d in date_order}
    fig = px.bar(
        x=list(ordered_counts.keys()),
        y=list(ordered_counts.values()),
        title="File Age Distribution",
        labels={"x": "Time Period", "y": "Number of Files"},
        color=list(ordered_counts.values()),
        color_continuous_scale="blues",
        height=300,
    )
    st.plotly_chart(fig, config={"responsive": True})

    st.subheader("🔍 File Extension Analysis")
    ext_counts = df["Extension"].value_counts().head(10)
    fig = px.bar(
        x=ext_counts.values,
        y=ext_counts.index,
        orientation="h",
        title="Top File Extensions",
        labels={"x": "Number of Files", "y": "Extension"},
        color=ext_counts.values,
        color_continuous_scale="plasma",
        height=300,
    )
    st.plotly_chart(fig, config={"responsive": True})

    st.subheader("💾 Storage Usage by File Type")
    storage_by_type = df.groupby("File Type")["Size (KB)"].sum().sort_values(ascending=False)
    storage_mb = storage_by_type / 1024
    fig = px.bar(
        x=storage_mb.index,
        y=storage_mb.values,
        title="Storage Usage by File Type (MB)",
        labels={"x": "File Type", "y": "Storage (MB)"},
        color=storage_mb.values,
        color_continuous_scale="sunset",
        height=300,
    )
    st.plotly_chart(fig, config={"responsive": True})

    display_df = df[["Icon", "File Name", "Size (KB)", "File Type", "Date Category", "Extension", "Location"]].copy()
    st.dataframe(display_df, width='stretch')

    if st.checkbox("🔍 Show File Previews"):
        st.subheader("🖼️ File Previews")
        for _, row in df.head(10).iterrows():
            with st.expander(f"{row['Icon']} {row['File Name']}"):
                col1, col2 = st.columns([1, 2])
                with col1:
                    st.write(f"**Size:** {row['Size (KB)']} KB")
                    st.write(f"**Type:** {row['File Type']}")
                    st.write(f"**Modified:** {row['Last Modified']}")
                    if row['Suspicious']:
                        st.warning(f"⚠️ Suspicious: {', '.join(row['Suspicious'])}")
                with col2:
                    if row['Preview'] and row['Preview'] != "Preview not available for this file type":
                        if str(row['Preview']).startswith('data:image'):
                            st.image(row['Preview'])
                        else:
                            st.text(row['Preview'])
                    else:
                        st.info("No preview available")

    st.markdown("---")
    st.subheader("🛡️ Security Analysis")
    suspicious_files = df[df['Suspicious'].apply(lambda x: len(x) > 0)]
    if not suspicious_files.empty:
        st.warning(f"⚠️ Found {len(suspicious_files)} potentially suspicious files!")
        for _, row in suspicious_files.iterrows():
            st.write(f"**{row['File Name']}**: {', '.join(row['Suspicious'])}")
    else:
        st.success("✅ No suspicious files detected!")

    if st.button("🔍 Analyze Duplicates"):
        duplicates = find_duplicates(all_files)
        if duplicates:
            st.warning(f"Found {len(duplicates)} groups of duplicate files!")
            for _, file_list in list(duplicates.items())[:10]:
                with st.expander(f"Duplicate Group ({len(file_list)} files)"):
                    for file_path in file_list:
                        st.write(f"- {os.path.basename(file_path)}")
        else:
            st.success("No duplicate files found!")

    st.markdown("---")
    st.subheader("📤 Export Options")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("📊 Export CSV"):
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name=f"file_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
            )
    with col2:
        if st.button("📋 Export JSON"):
            json_data = df.to_json(orient='records', indent=2)
            st.download_button(
                label="Download JSON",
                data=json_data,
                file_name=f"file_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
            )
    with col3:
        if st.button("📈 Generate Report"):
            type_counts = df["File Type"].value_counts()
            size_counts = df["Size Category"].value_counts()
            date_counts = df["Date Category"].value_counts()
            report = f"""
# File Analysis Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Folder: {folder}

## Summary
- Total Files: {len(df)}
- Total Size: {total_size:.2f} KB
- File Types: {len(df['File Type'].unique())}

## File Type Distribution
{type_counts.to_string()}

## Size Distribution
{size_counts.to_string()}

## Date Distribution
{date_counts.to_string()}
"""
            st.download_button(
                label="Download Report",
                data=report,
                file_name=f"file_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown",
            )

    return df, all_files
