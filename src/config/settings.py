# Configuration settings for File Organizer

# File type categories
FILE_CATEGORIES = {
    'image_exts': {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', '.svg', '.ico'},
    'video_exts': {'.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v'},
    'audio_exts': {'.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a', '.wma'},
    'doc_exts': {'.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt', '.pages'},
    'archive_exts': {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'},
    'code_exts': {'.py', '.js', '.html', '.css', '.java', '.cpp', '.c', '.php', '.rb', '.go'}
}

# File size categories
SIZE_CATEGORIES = {
    'small': 1024 * 1024,  # 1MB
    'medium': 100 * 1024 * 1024,  # 100MB
}

# File icons mapping
FILE_ICONS = {
    '.pdf': '📄', '.doc': '📝', '.docx': '📝', '.txt': '📄',
    '.jpg': '🖼️', '.jpeg': '🖼️', '.png': '🖼️', '.gif': '🖼️',
    '.mp4': '🎬', '.avi': '🎬', '.mkv': '🎬', '.mov': '🎬',
    '.mp3': '🎵', '.wav': '🎵', '.flac': '🎵',
    '.zip': '📦', '.rar': '📦', '.7z': '📦',
    '.py': '🐍', '.js': '📜', '.html': '🌐', '.css': '🎨',
    '.exe': '⚙️', '.msi': '⚙️'
}

# Common directories for Linux / cloud
COMMON_DIRECTORIES = [
    '/tmp', '/var/tmp', '/opt', '/usr/local', '/home', '/root'
]

# User subdirectories
USER_SUBDIRECTORIES = [
    'Downloads', 'Documents', 'Desktop', 'Pictures', 'Videos', 'Music', 'Projects', 'Code', 'src'
]
