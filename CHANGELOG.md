# Changelog

All notable changes to the Cowrie Processor script will be documented in this file.

## [2025-09-14] - Upstream backports, docs, and tooling

### Added
- Google-style docstrings across all modules (`process_cowrie.py`, `cowrie_malware_enrichment.py`, `submit_vtfiles.py`).
- `pyproject.toml` with explicit `py-modules`, runtime dependencies, and build metadata for uv-managed environments.
- Ruff and MyPy configuration under `pyproject.toml` with dev dependencies (`ruff`, `mypy`, `types-requests`).
- New CLI argument `--urlhausapi` for authenticated URLhaus lookups. When omitted, URLhaus lookups are skipped.

### Changed
- Import order and formatting standardized; long lines and bare `except` replaced to satisfy Ruff.
- Minor refactors to avoid variable shadowing and improve type clarity (Path vs str) for MyPy.
- License field in `pyproject.toml` updated to SPDX string (`BSD-4-Clause`).
- README updated to document `--urlhausapi` usage and examples.

### Fixed
- Backported upstream fixes around URLhaus handling:
  - Add Auth-Key header support for URLhaus API.
  - Guard URLhaus calls and output when no API key is provided.
  - Improve robustness around JSON parsing in external API responses.
- Resolved MyPy issues in file iteration and command count aggregation.

### Tooling
- Target Python 3.13 for tooling (Ruff `py313`, MyPy `python_version = "3.13"`), while keeping runtime requirement at Python 3.8+.
- All files pass `ruff check .` and `mypy .` in CI-like runs with uv.

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
## [Unreleased]
### Added
- Central SQLite database support with per-sensor tagging via `--sensor` and `--db` (tables now include `hostname`).
- SQLite runtime tuning for central DB (WAL mode, `busy_timeout=5000`).
- Elasticsearch write via ILM write aliases in `es_reports.py` (daily/weekly/monthly `*-write`).
- ILM policies guidance updated to keep indices forever (no delete): daily hot 7d -> cold, weekly hot 30d -> cold, monthly hot 90d -> cold.
- Per-sensor and aggregate daily reports; weekly and monthly rollups from daily docs.
- Orchestration script `orchestrate_sensors.py` with TOML config (`sensors.example.toml`).
- Environment variable `ES_VERIFY_SSL=false` support in `es_reports.py`.
- Requirements updated: `elasticsearch>=8,<9` and `tomli` (for Python <3.11).
- API robustness in `process_cowrie.py`: HTTP timeouts, retries with backoff, and per-service rate limiting; `indicator_cache` table with TTLs for hashes/IPs to reduce API load.
- Refresh utility `refresh_cache_and_reports.py` to renew indicator cache and reindex recent daily/weekly/monthly reports within hot windows.
- Configurable report output directory:
  - New `--output-dir` flag in `process_cowrie.py`.
  - TOML support for `report_dir` (global or per-sensor) in `orchestrate_sensors.py`.
  - Default output base derived from `logpath` (`<logpath>/../reports`); final layout `<output-base>/<sensor>/<timestamp>/`.

### Changed
- README documentation expanded: central DB usage, ES reporting, write aliases, and orchestration.
- Deployment guidance references write aliases for ILM consistency.
 - ILM policies updated to never delete; daily hot 7d -> cold, weekly hot 30d -> cold, monthly hot 90d -> cold.
- Dropbox DB upload now reads from `--db` path reliably.
- Process compressed logs (`.bz2`, `.gz`) and skip malformed lines to avoid decode crashes.

### Notes
- Historical merge is not required; rebuild from retained raw logs is recommended.
- For concurrent writers, stagger processor runs slightly to minimize DB locks.

### Removed
- Deprecated `reports_index_template.json` in favor of per-type index templates and write aliases.

### Fixed
- Summary report loop now iterates with `.items()` to avoid `TypeError` when unpacking dict keys.
