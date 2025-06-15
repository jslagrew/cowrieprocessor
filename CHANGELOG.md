# Changelog

All notable changes to the Cowrie Processor script will be documented in this file.

## [2024-06-15] - Major Updates

### Added
- New command line argument `--localpath` for specifying local report output directory (default: `/mnt/dshield/reports`)
- New command line argument `--datapath` for specifying database and working files directory (default: `/mnt/dshield/data`)
- Structured directory layout:
  - `/mnt/dshield/data/db/` - For SQLite database storage
  - `/mnt/dshield/data/temp/` - For temporary processing files
  - `/mnt/dshield/reports/` - For final report storage
- Automatic directory creation for all required paths
- Proper file path handling using `os.path.join()`
- Comprehensive error handling with logging for file operations
- Automatic cleanup of temporary files after processing
- Added virtual environment support for dependency management
- Added .gitignore file for repository management
- Added CHANGELOG.md for tracking changes

### Changed
- Removed deprecated `distutils` import
- Updated file handling to use absolute paths
- Improved file organization with dedicated directories
- Enhanced error handling and logging throughout the script
- Modified report generation to ensure files are created in correct locations
- Updated database storage location to dedicated directory
- Moved to virtual environment for dependency management
- Prepared repository for GitHub hosting

### Fixed
- Fixed bzip2 file handling for compressed log files
- Fixed file path construction for reports and database
- Fixed abnormal report generation and copying
- Fixed temporary directory cleanup
- Fixed file permission issues with proper directory creation

### Dependencies
- Updated requirements.txt with necessary packages:
  - requests>=2.31.0
  - dropbox>=11.36.2
  - ipaddress>=1.0.23
  - pathlib>=1.0.1
  - python-dateutil>=2.8.2

## [Previous Versions]

### Original Features
- Cowrie log processing
- VirusTotal integration
- DShield IP lookup
- URLhaus integration
- SPUR.us data enrichment
- Dropbox upload capability
- SQLite database storage
- Session analysis
- Command tracking
- File download/upload tracking
- Abnormal attack detection
- Report generation 