import os
import psutil
from pathlib import Path

from src.config.settings import COMMON_DIRECTORIES, USER_SUBDIRECTORIES


def get_available_drives() -> list[str]:
    drives: list[str] = []
    # Common directories
    for dir_path in COMMON_DIRECTORIES:
        try:
            if os.path.exists(dir_path) and os.path.isdir(dir_path) and os.access(dir_path, os.R_OK):
                drives.append(dir_path)
        except Exception:
            continue
    # Home and common subdirs
    try:
        home_dir = os.path.expanduser("~")
        if home_dir and home_dir not in drives:
            drives.append(home_dir)
        for subdir in USER_SUBDIRECTORIES:
            dir_path = os.path.join(home_dir, subdir)
            if os.path.exists(dir_path) and os.path.isdir(dir_path):
                drives.append(dir_path)
    except Exception:
        pass
    # Mount points
    try:
        partitions = psutil.disk_partitions(all=False)
        mount_points = [p.mountpoint for p in partitions if os.path.exists(p.mountpoint) and os.path.isdir(p.mountpoint)]
        for mount_point in mount_points:
            if mount_point not in drives and os.access(mount_point, os.R_OK):
                drives.append(mount_point)
    except Exception:
        pass
    # Fallback
    if not drives:
        try:
            drives.append(os.getcwd())
        except Exception:
            drives.append("/tmp")
    return drives


def validate_directory_access(directory_path: str) -> tuple[bool, str]:
    try:
        path = Path(directory_path)
        if not path.exists():
            return False, f"Directory '{directory_path}' does not exist."
        if not path.is_dir():
            return False, f"'{directory_path}' is not a directory."
        if not os.access(directory_path, os.R_OK):
            return False, f"No read permission for '{directory_path}'."
        return True, "Directory is accessible"
    except Exception as e:
        return False, f"Error accessing '{directory_path}': {str(e)}"


def get_directory_contents(directory_path: str) -> list[tuple[str, Path]]:
    base_dir = Path(directory_path)
    folder_options: list[tuple[str, Path]] = [(f"📁 Root of {directory_path}", base_dir)]
    try:
        subdirs = [
            (f"📂 {f.name}", f)
            for f in base_dir.iterdir()
            if f.is_dir() and os.access(f, os.R_OK)
        ]
        folder_options.extend(subdirs)
    except PermissionError:
        pass
    return folder_options
