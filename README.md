# 🗃️ File Organizer & Virus Scanner

A comprehensive file management and security tool built with Streamlit that helps you organize, analyze, and secure your files.

## ✨ Features

### 🗂️ File Organization
- **Organize by Extension** - Group files by their file extensions
- **Organize by Type** - Categorize files by type (Images, Videos, Documents, etc.)
- **Organize by Date** - Sort files by modification date (Today, This Week, This Month, etc.)
- **Organize by Size** - Group files by size categories (Small, Medium, Large)
- **Find Duplicates** - Detect and manage duplicate files using hash comparison
- **Create Archives** - Compress files into ZIP/TAR archives

### 📊 File Analysis
- **Interactive Charts** - Beautiful Plotly visualizations for file statistics
- **File Type Distribution** - See what types of files you have
- **Size Analysis** - Understand your storage usage patterns
- **Date Analysis** - Track file age and activity
- **Storage Usage** - Monitor disk usage by file type
- **File Search** - Search files by name, extension, or content

### 🛡️ Security Features
- **Virus Scanning** - Integration with VirusTotal API for malware detection
- **File Integrity** - Calculate and verify file checksums (MD5, SHA256)
- **Suspicious File Detection** - Flag potentially dangerous files
- **Permission Analysis** - Check file permissions and ownership
- **Security Reports** - Comprehensive security analysis

### 🔧 Bulk Operations
- **Batch Renaming** - Rename multiple files with custom patterns
- **Empty Folder Cleanup** - Remove empty directories
- **File Sorting** - Sort files by various criteria
- **Bulk File Operations** - Perform actions on multiple files

### 📤 Export & Reporting
- **CSV Export** - Export file analysis data
- **JSON Export** - Machine-readable data export
- **Markdown Reports** - Generate comprehensive reports
- **File Previews** - Preview images and text files

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Aditya-Nagurkar/fileOrganizer.git
   cd fileOrganizer
   ```

2. **Install dependencies**
   ```bash
   pip install streamlit pandas psutil pillow plotly requests
   ```

3. **Set up VirusTotal API (Optional)**
   - Get a free API key from [VirusTotal](https://www.virustotal.com)
   - Create `.streamlit/secrets.toml`:
     ```toml
     VIRUSTOTAL_API_KEY = "your_api_key_here"
     ```

4. **Run the application**
   ```bash
   streamlit run file_organizer.py
   ```

## 🔧 Configuration

### Streamlit Secrets
Create `.streamlit/secrets.toml` for secure configuration:
```toml
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
```

### Environment Variables
Alternatively, set environment variables:
```bash
export VIRUSTOTAL_API_KEY="your_api_key_here"
```

## 📁 Project Structure

```
file-organizer/
├── file_organizer.py          # Main application
├── .streamlit/
│   └── secrets.toml           # API keys and secrets
├── .gitignore                 # Git ignore rules
└── README.md                  # This file
```

## 🎨 Features Overview

### File Organization Options
- **6 Organization Methods** - Extension, Type, Date, Size, Duplicates, Archives
- **Smart Categorization** - Automatic file type detection
- **Custom Patterns** - Flexible renaming and organization rules

### Advanced Analytics
- **Interactive Charts** - Plotly-powered visualizations
- **Real-time Statistics** - Live file analysis
- **Storage Insights** - Disk usage optimization
- **Trend Analysis** - File activity patterns

### Security & Safety
- **VirusTotal Integration** - Professional malware scanning
- **File Integrity** - Checksum verification
- **Safe Operations** - Non-destructive file management
- **Backup Options** - Archive before organizing

## 🔒 Security Notes

- **API Keys**: Never commit API keys to version control
- **File Access**: The app only reads and organizes files you explicitly select
- **Permissions**: Respects file system permissions
- **Backup**: Always backup important files before bulk operations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Streamlit** - For the amazing web framework
- **Plotly** - For beautiful interactive charts
- **VirusTotal** - For the security API
- **PIL/Pillow** - For image processing
- **psutil** - For system information

## 📞 Support

If you encounter any issues or have questions:
- Open an issue on GitHub
- Check the documentation
- Review the code comments

---

**Made with ❤️ for better file management**
