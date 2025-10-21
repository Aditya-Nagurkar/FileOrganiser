import os
import shutil
import requests
import hashlib
import time
import streamlit as st
import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta
import psutil
import zipfile
import tarfile
import mimetypes
from PIL import Image
import base64
import io
import json
from collections import defaultdict, Counter
import re
import plotly.express as px
import plotly.graph_objects as go


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

def get_available_drives():
    """Get available drives and common directories on Linux"""
    drives = []
    
    # Get mount points from psutil
    partitions = psutil.disk_partitions(all=False)
    mount_points = [p.mountpoint for p in partitions if os.path.exists(p.mountpoint) and os.path.isdir(p.mountpoint)]
    drives.extend(mount_points)
    
    # Add common user directories
    home_dir = os.path.expanduser("~")
    common_dirs = [
        home_dir,
        os.path.join(home_dir, "Downloads"),
        os.path.join(home_dir, "Documents"),
        os.path.join(home_dir, "Desktop"),
        os.path.join(home_dir, "Pictures"),
        os.path.join(home_dir, "Videos"),
        os.path.join(home_dir, "Music"),
        "/tmp",
        "/var/tmp"
    ]
    
    # Add common directories that exist
    for dir_path in common_dirs:
        if os.path.exists(dir_path) and os.path.isdir(dir_path) and dir_path not in drives:
            drives.append(dir_path)
    
    return drives

available_drives = get_available_drives()


def check_virus_total(file_path, api_key):
    """
    Checks file hash on VirusTotal.
    Returns: "✅ Clean", "⚠️ Infected", or "❓ Unknown"
    """
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
            if malicious > 0 or suspicious > 0:
                return "⚠️ Infected"
            else:
                return "✅ Clean"
        else:
            return "❓ Unknown"
    except Exception as e:
        return f"Error: {e}"

def get_virustotal_api_key():
    """Return VirusTotal API key from Streamlit secrets or environment.

    Lookup order:
    1) st.secrets["VIRUSTOTAL_API_KEY"] if defined
    2) os.environ["VIRUSTOTAL_API_KEY"]
    Returns None if not found.
    """
    try:
        # st.secrets behaves like a mapping and supports get()
        key = st.secrets.get("VIRUSTOTAL_API_KEY")
    except Exception:
        key = None
    if not key:
        key = os.environ.get("VIRUSTOTAL_API_KEY")
    return key

# File categorization functions
def get_file_category(file_path):
    """Categorize file by type"""
    ext = Path(file_path).suffix.lower()
    
    image_exts = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', '.svg', '.ico'}
    video_exts = {'.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v'}
    audio_exts = {'.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a', '.wma'}
    doc_exts = {'.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt', '.pages'}
    archive_exts = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'}
    code_exts = {'.py', '.js', '.html', '.css', '.java', '.cpp', '.c', '.php', '.rb', '.go'}
    
    if ext in image_exts:
        return "🖼️ Images"
    elif ext in video_exts:
        return "🎬 Videos"
    elif ext in audio_exts:
        return "🎵 Audio"
    elif ext in doc_exts:
        return "📄 Documents"
    elif ext in archive_exts:
        return "📦 Archives"
    elif ext in code_exts:
        return "💻 Code"
    else:
        return "📁 Other"

def get_file_size_category(size_bytes):
    """Categorize file by size"""
    if size_bytes < 1024 * 1024:  # < 1MB
        return "Small"
    elif size_bytes < 100 * 1024 * 1024:  # < 100MB
        return "Medium"
    else:
        return "Large"

def get_date_category(file_path):
    """Categorize file by modification date"""
    try:
        mtime = os.path.getmtime(file_path)
        file_date = datetime.fromtimestamp(mtime)
        now = datetime.now()
        
        if file_date.date() == now.date():
            return "Today"
        elif file_date.date() == (now - timedelta(days=1)).date():
            return "Yesterday"
        elif file_date > now - timedelta(days=7):
            return "This Week"
        elif file_date > now - timedelta(days=30):
            return "This Month"
        else:
            return "Older"
    except:
        return "Unknown"

def calculate_file_hash(file_path, algorithm='md5'):
    """Calculate file hash for integrity checking"""
    hash_obj = hashlib.new(algorithm)
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except:
        return None

def detect_suspicious_file(file_path):
    """Detect potentially suspicious files"""
    suspicious_indicators = []
    
    # Check for double extensions
    name = Path(file_path).name
    if name.count('.') > 1:
        suspicious_indicators.append("Double extension")
    
    # Check for executable extensions in non-executable locations
    exe_exts = {'.exe', '.bat', '.cmd', '.scr', '.pif', '.com'}
    if Path(file_path).suffix.lower() in exe_exts:
        suspicious_indicators.append("Executable file")
    
    # Check for very large files
    try:
        size = os.path.getsize(file_path)
        if size > 500 * 1024 * 1024:  # > 500MB
            suspicious_indicators.append("Very large file")
    except:
        pass
    
    return suspicious_indicators

def get_file_icon(extension):
    """Get emoji icon for file type"""
    ext = extension.lower()
    icons = {
        '.pdf': '📄', '.doc': '📝', '.docx': '📝', '.txt': '📄',
        '.jpg': '🖼️', '.jpeg': '🖼️', '.png': '🖼️', '.gif': '🖼️',
        '.mp4': '🎬', '.avi': '🎬', '.mkv': '🎬', '.mov': '🎬',
        '.mp3': '🎵', '.wav': '🎵', '.flac': '🎵',
        '.zip': '📦', '.rar': '📦', '.7z': '📦',
        '.py': '🐍', '.js': '📜', '.html': '🌐', '.css': '🎨',
        '.exe': '⚙️', '.msi': '⚙️'
    }
    return icons.get(ext, '📄')

def create_archive(files, archive_path, archive_type='zip'):
    """Create archive from list of files"""
    try:
        if archive_type == 'zip':
            with zipfile.ZipFile(archive_path, 'w') as zipf:
                for file_path in files:
                    zipf.write(file_path, os.path.basename(file_path))
        elif archive_type == 'tar':
            with tarfile.open(archive_path, 'w') as tarf:
                for file_path in files:
                    tarf.add(file_path, os.path.basename(file_path))
        return True
    except Exception as e:
        st.error(f"Error creating archive: {e}")
        return False

def find_duplicates(files):
    """Find duplicate files by hash"""
    hash_to_files = defaultdict(list)
    
    for file_path in files:
        file_hash = calculate_file_hash(file_path)
        if file_hash:
            hash_to_files[file_hash].append(file_path)
    
    duplicates = {hash_val: file_list for hash_val, file_list in hash_to_files.items() if len(file_list) > 1}
    return duplicates

def get_file_preview(file_path, max_size=1024*1024):
    """Get file preview for display"""
    try:
        ext = Path(file_path).suffix.lower()
        
        if ext in {'.jpg', '.jpeg', '.png', '.gif', '.bmp'}:
            # Image preview
            img = Image.open(file_path)
            img.thumbnail((200, 200))
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()
            return f"data:image/png;base64,{img_str}"
        
        elif ext in {'.txt', '.py', '.js', '.html', '.css', '.json'}:
            # Text preview
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(max_size)
                return content[:500] + "..." if len(content) > 500 else content
        
        else:
            return "Preview not available for this file type"
    except:
        return "Error loading preview"

# Add custom path option
st.subheader("📁 Select Directory")

selected_drive = st.selectbox("💽 Select from common directories:", options=available_drives)

if selected_drive:
    BASE_DIR = Path(selected_drive)

    try:
        folder_options = [
            (f"📁 Root of {selected_drive}", BASE_DIR)
        ] + [
            (f"📂 {f.name}", f)
            for f in BASE_DIR.iterdir()
            if f.is_dir()
        ]
    except PermissionError:
        st.error("🚫 Access denied to this drive or folder.")
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
        
        # Enhanced file organization options
        st.markdown("---")
        st.subheader("🗂️ File Organization Options")
        
        # Create a grid layout with better spacing
        st.markdown("""
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
        """, unsafe_allow_html=True)
        
        # Row 1: Basic organization
        col1, col2, col3 = st.columns(3, gap="medium")
        
        with col1:
            if st.button("📦 Organize by Extension", use_container_width=True, key="ext_btn"):
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
            if st.button("🏷️ Organize by Type", use_container_width=True, key="type_btn"):
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
            if st.button("📅 Organize by Date", use_container_width=True, key="date_btn"):
                moved_files = 0
                for file in os.listdir(folder):
                    file_path = os.path.join(folder, file)
                    try:
                        if os.path.isfile(file_path):
                            date_cat = get_date_category(file_path)
                            target_folder = os.path.join(folder, date_cat)
                            os.makedirs(target_folder, exist_ok=True)
                            shutil.move(file_path, os.path.join(target_folder, file))
                            moved_files += 1
                    except (FileNotFoundError, PermissionError, OSError):
                        continue
                st.success(f"✅ Organized {moved_files} file(s) by date!")
        
        # Row 2: Advanced organization
        col4, col5, col6 = st.columns(3, gap="medium")
        
        with col4:
            if st.button("📏 Organize by Size", use_container_width=True, key="size_btn"):
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
            if st.button("🔍 Find Duplicates", use_container_width=True, key="dup_btn"):
                all_files = []
                for root, _, files in os.walk(folder):
                    for file in files:
                        all_files.append(os.path.join(root, file))
                
                duplicates = find_duplicates(all_files)
                if duplicates:
                    st.warning(f"Found {len(duplicates)} groups of duplicate files!")
                    for hash_val, file_list in list(duplicates.items())[:5]:  # Show first 5 groups
                        st.write(f"**Duplicate group:** {len(file_list)} files")
                        for file_path in file_list:
                            st.write(f"- {os.path.basename(file_path)}")
                else:
                    st.success("No duplicate files found!")
        
        with col6:
            if st.button("📦 Create Archive", use_container_width=True, key="arch_btn"):
                all_files = []
                for root, _, files in os.walk(folder):
                    for file in files:
                        all_files.append(os.path.join(root, file))
                
                if all_files:
                    archive_path = os.path.join(folder, f"archive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
                    if create_archive(all_files, archive_path):
                        st.success(f"✅ Created archive: {os.path.basename(archive_path)}")
                    else:
                        st.error("❌ Failed to create archive")
                else:
                    st.info("No files to archive")
        
        # Bulk operations and file renaming
        st.markdown("---")
        st.subheader("🔧 Bulk Operations")
        
        # Batch file renaming
        st.write("**📝 Batch File Renaming**")
        rename_pattern = st.text_input("Rename pattern:", placeholder="file_{i:03d} (will create file_001, file_002, etc.)")
        col_rename1, col_rename2 = st.columns([3, 1])
        with col_rename1:
            if st.button("🔄 Rename Files", use_container_width=True) and rename_pattern:
                renamed_count = 0
                for i, file in enumerate(os.listdir(folder)):
                    file_path = os.path.join(folder, file)
                    if os.path.isfile(file_path):
                        try:
                            ext = os.path.splitext(file)[1]
                            new_name = rename_pattern.format(i=i+1) + ext
                            new_path = os.path.join(folder, new_name)
                            os.rename(file_path, new_path)
                            renamed_count += 1
                        except:
                            continue
                st.success(f"✅ Renamed {renamed_count} files!")
        
        st.markdown("---")
        
        # Other bulk operations
        st.write("**🗑️ Other Bulk Operations**")
        col_bulk1, col_bulk2 = st.columns(2)
        
        with col_bulk1:
            if st.button("🗑️ Delete Empty Folders", use_container_width=True):
                deleted_count = 0
                for root, dirs, files in os.walk(folder, topdown=False):
                    for dir_name in dirs:
                        dir_path = os.path.join(root, dir_name)
                        try:
                            if not os.listdir(dir_path):  # Empty directory
                                os.rmdir(dir_path)
                                deleted_count += 1
                        except:
                            continue
                st.success(f"✅ Deleted {deleted_count} empty folders!")
        
        with col_bulk2:
            if st.button("📏 Sort by Size", use_container_width=True):
                files_with_size = []
                for file in os.listdir(folder):
                    file_path = os.path.join(folder, file)
                    if os.path.isfile(file_path):
                        files_with_size.append((file, os.path.getsize(file_path)))
                
                files_with_size.sort(key=lambda x: x[1], reverse=True)  # Sort by size, largest first
                
                for i, (file, size) in enumerate(files_with_size):
                    try:
                        ext = os.path.splitext(file)[1]
                        new_name = f"file_{i+1:03d}_{size//1024}KB{ext}"
                        old_path = os.path.join(folder, file)
                        new_path = os.path.join(folder, new_name)
                        os.rename(old_path, new_path)
                    except:
                        continue
                st.success("✅ Files sorted by size!")

        # Enhanced file analysis
        st.markdown("---")
        st.subheader("📊 File Analysis & Statistics")
        
        # File search
        search_term = st.text_input("🔍 Search files:", placeholder="Enter filename, extension, or content...")
        
        file_list = []
        all_files = []
        
        for root, _, files in os.walk(folder):
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    stats = os.stat(file_path)
                    
                    # Enhanced file information
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
                        "Preview": get_file_preview(file_path) if os.path.getsize(file_path) < 10*1024*1024 else "File too large for preview"
                    }
                    
                    # Apply search filter
                    if search_term:
                        search_lower = search_term.lower()
                        if (search_lower in file.lower() or 
                            search_lower in file_info["Extension"] or 
                            search_lower in file_info["File Type"].lower()):
                            file_list.append(file_info)
                    else:
                        file_list.append(file_info)
                    
                    all_files.append(file_path)
                    
                except (FileNotFoundError, PermissionError, OSError):
                    continue

        if file_list:
            df = pd.DataFrame(file_list)
            
            # Display files with enhanced information
            st.subheader("📄 Files in Folder")
            
            # Show file count and total size
            total_size = df["Size (KB)"].sum()
            st.metric("Total Files", len(df))
            st.metric("Total Size", f"{total_size:.2f} KB")
            
            # Enhanced file type distribution
            st.subheader("📊 File Type Distribution")
            type_counts = df["File Type"].value_counts()
            
            # Create a more detailed chart with proper formatting
            type_df = pd.DataFrame({
                'File Type': type_counts.index,
                'Count': type_counts.values,
                'Percentage': (type_counts.values / type_counts.sum() * 100).round(1)
            })
            
            col1, col2 = st.columns([2, 1])
            with col1:
                # Beautiful Plotly bar chart
                fig = px.bar(
                    x=type_counts.index, 
                    y=type_counts.values,
                    title="File Type Distribution",
                    labels={'x': 'File Type', 'y': 'Number of Files'},
                    color=type_counts.values,
                    color_continuous_scale='viridis',
                    height=400
                )
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white'),
                    xaxis=dict(tickangle=45),
                    showlegend=False
                )
                st.plotly_chart(fig, use_container_width=True)
            with col2:
                st.dataframe(type_df, use_container_width=True)
            
            # Size distribution with better visualization
            st.subheader("📏 File Size Distribution")
            size_counts = df["Size Category"].value_counts()
            
            col1, col2 = st.columns([2, 1])
            with col1:
                # Beautiful pie chart for size distribution
                fig = px.pie(
                    values=size_counts.values,
                    names=size_counts.index,
                    title="File Size Distribution",
                    color_discrete_sequence=px.colors.qualitative.Set3,
                    height=400
                )
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white'),
                    showlegend=True
                )
                st.plotly_chart(fig, use_container_width=True)
            with col2:
                # Show size statistics
                total_size_mb = df["Size (KB)"].sum() / 1024
                avg_size_kb = df["Size (KB)"].mean()
                largest_file = df.loc[df["Size (KB)"].idxmax(), "File Name"]
                largest_size = df["Size (KB)"].max()
                
                st.metric("Total Size", f"{total_size_mb:.1f} MB")
                st.metric("Average Size", f"{avg_size_kb:.1f} KB")
                st.metric("Largest File", f"{largest_size:.1f} KB")
                st.caption(f"Largest: {largest_file}")
            
            # Enhanced date distribution
            st.subheader("📅 File Age Distribution")
            date_counts = df["Date Category"].value_counts()
            
            # Create a timeline-style visualization
            date_order = ["Today", "Yesterday", "This Week", "This Month", "Older", "Unknown"]
            ordered_counts = {date: date_counts.get(date, 0) for date in date_order}
            
            col1, col2 = st.columns([2, 1])
            with col1:
                # Timeline-style bar chart
                fig = px.bar(
                    x=list(ordered_counts.keys()),
                    y=list(ordered_counts.values()),
                    title="File Age Distribution",
                    labels={'x': 'Time Period', 'y': 'Number of Files'},
                    color=list(ordered_counts.values()),
                    color_continuous_scale='blues',
                    height=300
                )
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white'),
                    xaxis=dict(tickangle=45),
                    showlegend=False
                )
                st.plotly_chart(fig, use_container_width=True)
            with col2:
                # Show date statistics
                recent_files = df[df["Date Category"].isin(["Today", "Yesterday", "This Week"])]["File Name"].count()
                old_files = df[df["Date Category"] == "Older"]["File Name"].count()
                
                st.metric("Recent Files", recent_files)
                st.metric("Old Files", old_files)
                st.metric("Total Categories", len(date_counts))
            
            # File extension analysis
            st.subheader("🔍 File Extension Analysis")
            ext_counts = df["Extension"].value_counts().head(10)  # Top 10 extensions
            
            col1, col2 = st.columns([2, 1])
            with col1:
                # Horizontal bar chart for extensions
                fig = px.bar(
                    x=ext_counts.values,
                    y=ext_counts.index,
                    orientation='h',
                    title="Top File Extensions",
                    labels={'x': 'Number of Files', 'y': 'Extension'},
                    color=ext_counts.values,
                    color_continuous_scale='plasma',
                    height=300
                )
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white'),
                    showlegend=False
                )
                st.plotly_chart(fig, use_container_width=True)
            with col2:
                st.write("**Top Extensions:**")
                for ext, count in ext_counts.head(5).items():
                    st.write(f"• {ext}: {count} files")
            
            # Storage usage by file type
            st.subheader("💾 Storage Usage by File Type")
            storage_by_type = df.groupby("File Type")["Size (KB)"].sum().sort_values(ascending=False)
            storage_mb = storage_by_type / 1024  # Convert to MB
            
            col1, col2 = st.columns([2, 1])
            with col1:
                # Storage usage chart with gradient colors
                fig = px.bar(
                    x=storage_mb.index,
                    y=storage_mb.values,
                    title="Storage Usage by File Type (MB)",
                    labels={'x': 'File Type', 'y': 'Storage (MB)'},
                    color=storage_mb.values,
                    color_continuous_scale='sunset',
                    height=300
                )
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white'),
                    xaxis=dict(tickangle=45),
                    showlegend=False
                )
                st.plotly_chart(fig, use_container_width=True)
            with col2:
                st.write("**Storage Usage:**")
                for file_type, size_mb in storage_mb.head(5).items():
                    st.write(f"• {file_type}: {size_mb:.1f} MB")
            
            # Enhanced file table with icons
            display_df = df[["Icon", "File Name", "Size (KB)", "File Type", "Date Category", "Extension", "Location"]].copy()
            st.dataframe(display_df, use_container_width=True)
            
            # File preview section
            if st.checkbox("🔍 Show File Previews"):
                st.subheader("🖼️ File Previews")
                for i, row in df.head(10).iterrows():  # Show first 10 files
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
                                if row['Preview'].startswith('data:image'):
                                    st.image(row['Preview'])
                                else:
                                    st.text(row['Preview'])
                            else:
                                st.info("No preview available")
            
            # Security analysis
            st.markdown("---")
            st.subheader("🛡️ Security Analysis")
            
            suspicious_files = df[df['Suspicious'].apply(lambda x: len(x) > 0)]
            if not suspicious_files.empty:
                st.warning(f"⚠️ Found {len(suspicious_files)} potentially suspicious files!")
                for _, row in suspicious_files.iterrows():
                    st.write(f"**{row['File Name']}**: {', '.join(row['Suspicious'])}")
            else:
                st.success("✅ No suspicious files detected!")
            
            # Duplicate analysis
            if st.button("🔍 Analyze Duplicates"):
                duplicates = find_duplicates(all_files)
                if duplicates:
                    st.warning(f"Found {len(duplicates)} groups of duplicate files!")
                    for hash_val, file_list in list(duplicates.items())[:10]:
                        with st.expander(f"Duplicate Group ({len(file_list)} files)"):
                            for file_path in file_list:
                                st.write(f"- {os.path.basename(file_path)}")
                else:
                    st.success("No duplicate files found!")
            
            # Export options
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
                        mime="text/csv"
                    )
            
            with col2:
                if st.button("📋 Export JSON"):
                    json_data = df.to_json(orient='records', indent=2)
                    st.download_button(
                        label="Download JSON",
                        data=json_data,
                        file_name=f"file_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
            
            with col3:
                if st.button("📈 Generate Report"):
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
                        mime="text/markdown"
                    )

            st.markdown("---")
            st.subheader("👾 Virus Scan")

            api_key = get_virustotal_api_key()

            if not api_key:
                st.error("VIRUSTOTAL_API_KEY is not set. Add it to Streamlit secrets or environment.")
            elif st.button("🚨 Scan Files for Viruses"):
                    st.write("🔍 Scanning files... please wait...")
                    results = []
                    progress_bar = st.progress(0)
                    total = len(df)

                    for i, (_, row) in enumerate(df.iterrows()):
                        file_path = os.path.join(folder, row["Location"], row["File Name"])
                        status = check_virus_total(file_path, api_key)
                        results.append(status)
                        progress_bar.progress((i + 1) / total)
                        time.sleep(1.5)  # to prevent API rate limit issues

                    df["Virus Check"] = results
                    st.success("✅ Virus scan completed!")
                    st.dataframe(df, use_container_width=True)
        else:
            st.info("📂 No files found in this folder.")
