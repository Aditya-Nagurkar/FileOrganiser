import os
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
import zipfile
import tarfile
from PIL import Image
import base64
import io

from src.config.settings import FILE_CATEGORIES, SIZE_CATEGORIES, FILE_ICONS


def get_file_category(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    if ext in FILE_CATEGORIES['image_exts']:
        return "🖼️ Images"
    if ext in FILE_CATEGORIES['video_exts']:
        return "🎬 Videos"
    if ext in FILE_CATEGORIES['audio_exts']:
        return "🎵 Audio"
    if ext in FILE_CATEGORIES['doc_exts']:
        return "📄 Documents"
    if ext in FILE_CATEGORIES['archive_exts']:
        return "📦 Archives"
    if ext in FILE_CATEGORIES['code_exts']:
        return "💻 Code"
    return "📁 Other"


def get_file_size_category(size_bytes: int) -> str:
    if size_bytes < SIZE_CATEGORIES['small']:
        return "Small"
    if size_bytes < SIZE_CATEGORIES['medium']:
        return "Medium"
    return "Large"


def get_date_category(file_path: str) -> str:
    try:
        mtime = os.path.getmtime(file_path)
        file_date = datetime.fromtimestamp(mtime)
        now = datetime.now()
        if file_date.date() == now.date():
            return "Today"
        if file_date.date() == (now - timedelta(days=1)).date():
            return "Yesterday"
        if file_date > now - timedelta(days=7):
            return "This Week"
        if file_date > now - timedelta(days=30):
            return "This Month"
        return "Older"
    except Exception:
        return "Unknown"


def calculate_file_hash(file_path: str, algorithm: str = 'md5') -> str | None:
    hash_obj = hashlib.new(algorithm)
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception:
        return None

def detect_suspicious_file(file_path: str) -> list[str]:
    suspicious: list[str] = []
    name = Path(file_path).name
    if name.count('.') > 1:
        suspicious.append("Double extension")
    exe_exts = {'.exe', '.bat', '.cmd', '.scr', '.pif', '.com'}
    if Path(file_path).suffix.lower() in exe_exts:
        suspicious.append("Executable file")
    try:
        size = os.path.getsize(file_path)
        if size > 500 * 1024 * 1024:
            suspicious.append("Very large file")
    except Exception:
        pass
    return suspicious


def get_file_icon(extension: str) -> str:
    return FILE_ICONS.get(extension.lower(), '📄')


def create_archive(files: list[str], archive_path: str, archive_type: str = 'zip') -> bool:
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
    except Exception:
        return False


def find_duplicates(files: list[str]) -> dict[str, list[str]]:
    hash_to_files: dict[str, list[str]] = defaultdict(list)
    for file_path in files:
        file_hash = calculate_file_hash(file_path)
        if file_hash:
            hash_to_files[file_hash].append(file_path)
    return {h: fl for h, fl in hash_to_files.items() if len(fl) > 1}


def get_file_preview(file_path: str, max_size: int = 1024 * 1024) -> str:
    try:
        ext = Path(file_path).suffix.lower()
        if ext in {'.jpg', '.jpeg', '.png', '.gif', '.bmp'}:
            img = Image.open(file_path)
            img.thumbnail((200, 200))
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()
            return f"data:image/png;base64,{img_str}"
        if ext in {'.txt', '.py', '.js', '.html', '.css', '.json'}:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(max_size)
                return content[:500] + "..." if len(content) > 500 else content
        return "Preview not available for this file type"
    except Exception:
        return "Error loading preview"
