# Cowrie Processor

A Python script for processing and analyzing Cowrie honeypot logs, with integration to various security services.

## Features

- Process Cowrie JSON log files (including bzip2 compressed files)
- VirusTotal integration for file analysis
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

## Requirements

- Python 3.8 or higher
- Virtual environment (recommended)
- For Elasticsearch reporting and orchestration:
  - `elasticsearch>=8,<9`
  - `tomli` (if Python < 3.11)

## Installation

1. Clone the repository:
```bash
git clone git@github.com:datagen24/cowrieprocessor.git
cd cowrieprocessor
```

2. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Linux/Mac
# or
.\venv\Scripts\activate  # On Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python process_cowrie.py --logpath /path/to/cowrie/logs --email your.email@example.com
```

### Command Line Arguments

- `--logpath`: Path of cowrie json log files (default: '/srv/cowrie/var/log/cowrie')
- `--ttyfile`: Name of TTY associated TTY log file
- `--downloadfile`: Name of downloaded file (matches file SHA-256 hash)
- `--session`: Cowrie session number
- `--vtapi`: VirusTotal API key (required for VT data lookup)
- `--email`: Your email address (required for DShield IP lookup)
- `--summarizedays`: Will summarize all attacks in the given number of days
- `--dbxapi`: Dropbox access token for use with Dropbox upload of summary text files
- `--dbxkey`: Dropbox app key to be used to get new short-lived API access key
- `--dbxsecret`: Dropbox app secret to be used to get new short-lived API access key
- `--dbxrefreshtoken`: Dropbox refresh token to be used to get new short-lived API access key
- `--spurapi`: SPUR.us API key to be used for SPUR.us data enrichment
- `--urlhausapi`: URLhaus API key to be used for URLhaus data enrichment (optional; if omitted, URLhaus lookups are skipped)
- `--localpath`: Local path for saving reports (default: '/mnt/dshield/reports')
- `--datapath`: Local path for database and working files (default: '/mnt/dshield/data')
- `--sensor`: Sensor name/hostname to tag data with; defaults to system hostname
- `--db`: Path to the central SQLite database (default: '../cowrieprocessor.sqlite')
- `--api-timeout`: HTTP timeout in seconds for external APIs (default: 15)
- `--api-retries`: Max retries for transient API failures (default: 3)
- `--api-backoff`: Exponential backoff base in seconds (default: 2.0)
- `--hash-ttl-days`: TTL for known file hash lookups (VT) (default: 30)
- `--hash-unknown-ttl-hours`: TTL to recheck VT for unknown hashes sooner (default: 12)
- `--ip-ttl-hours`: TTL for IP lookups (DShield/URLhaus/SPUR) (default: 12)
- `--rate-vt`: Max VirusTotal requests per minute (default: 4)
- `--rate-dshield`: Max DShield requests per minute (default: 30)
- `--rate-urlhaus`: Max URLhaus requests per minute (default: 30)
- `--rate-spur`: Max SPUR requests per minute (default: 30)

### Example

Process logs for the last 90 days with all integrations:
```bash
python process_cowrie.py \
    --logpath /mnt/dshield/aws-eastus-dshield/NSM/cowrie \
    --email your.email@example.com \
    --summarizedays 90 \
    --vtapi your_vt_api_key \
    --urlhausapi your_urlhaus_api_key \
    --spurapi your_spur_api_key \
    --dbxapi your_dropbox_api_key
```

## Directory Structure

The script uses the following directory structure:
- `/mnt/dshield/data/db/` - SQLite database storage
- `/mnt/dshield/data/temp/` - Temporary processing files
- `/mnt/dshield/reports/` - Final report storage

## Multi-Sensor Central Database

To aggregate statistics across multiple sensors, you can point all processors to a single central SQLite database and tag events with a sensor name via `--sensor`.

Example:
```
# Sensor A
python process_cowrie.py --sensor honeypot-a --logpath /mnt/dshield/a/NSM/cowrie --db /mnt/dshield/data/db/cowrieprocessor.sqlite --summarizedays 1

# Sensor B
python process_cowrie.py --sensor honeypot-b --logpath /mnt/dshield/b/NSM/cowrie --db /mnt/dshield/data/db/cowrieprocessor.sqlite --summarizedays 1
```

Notes:
- The database schema now includes a `hostname` field on `sessions`, `commands`, and `files` to disambiguate per-sensor data.
- Runtime change: SQLite now uses WAL and a busy timeout to improve central DB concurrency.
- If you are migrating existing per-sensor databases, run each sensor once with the new version and `--sensor` against the central DB to backfill going forward. Historical consolidation can be rebuilt from retained raw logs.

## API Request Handling (timeouts, retries, rate limits)

- All external API requests (VirusTotal, DShield, URLhaus, SPUR) use:
  - Timeouts (`--api-timeout`), retries (`--api-retries`) with exponential backoff (`--api-backoff`).
  - Simple per-service rate limiting with configurable requests-per-minute flags.
- The processor maintains an `indicator_cache` table to record last fetch time and cache payloads per service/key:
  - Services: `vt_file` (hash), `dshield_ip` (ip), `urlhaus_ip` (ip), `spur_ip` (ip)
  - TTLs governed by `--hash-ttl-days`, `--hash-unknown-ttl-hours`, and `--ip-ttl-hours`.
  - If cached and fresh, the processor uses the cached response and avoids network calls.

## Elasticsearch Reporting

Use `es_reports.py` to generate reports from the central SQLite database and index them into Elasticsearch.

Environment variables:
- `ES_HOST`, `ES_USERNAME`, `ES_PASSWORD` or `ES_API_KEY` / `ES_CLOUD_ID`
- `ES_VERIFY_SSL=false` to disable certificate verification (or pass `--no-ssl-verify`)

Write targets (ILM write aliases):
- Daily: `cowrie.reports.daily-write`
- Weekly: `cowrie.reports.weekly-write`
- Monthly: `cowrie.reports.monthly-write`

Examples:
```bash
# Aggregate and per-sensor daily
python es_reports.py daily --all-sensors --db /mnt/dshield/data/db/cowrieprocessor.sqlite --date 2025-09-14

# Single sensor
python es_reports.py daily --sensor honeypot-a --db /mnt/dshield/data/db/cowrieprocessor.sqlite --date 2025-09-14

# Backfill range
python es_reports.py backfill --start 2025-09-01 --end 2025-09-14 --db /mnt/dshield/data/db/cowrieprocessor.sqlite

# Weekly and monthly rollups
python es_reports.py weekly --week 2025-W37 --db /mnt/dshield/data/db/cowrieprocessor.sqlite
python es_reports.py monthly --month 2025-09 --db /mnt/dshield/data/db/cowrieprocessor.sqlite
```

ILM/Template notes:
- Policies are configured to never delete, only move to cold: daily after 7d, weekly after 30d, monthly after 90d.
- Ensure initial indices exist with the write aliases as rollover aliases, e.g. `cowrie.reports.daily-000001` with alias `cowrie.reports.daily-write`.
- The reporter writes to the `*-write` alias; searches can use `cowrie.reports.daily-*`.

## Orchestrating Multiple Sensors (TOML)

Use `orchestrate_sensors.py` with a TOML file to run multiple sensors sequentially.

```toml
[global]
db = "/mnt/dshield/data/db/cowrieprocessor.sqlite"

[[sensor]]
name = "honeypot-a"
logpath = "/mnt/dshield/a/NSM/cowrie"
summarizedays = 1
email = "you@example.com"

[[sensor]]
name = "honeypot-b"
logpath = "/mnt/dshield/b/NSM/cowrie"
summarizedays = 1
```

Run:
```bash
python orchestrate_sensors.py --config sensors.toml --max-retries 3 --pause-seconds 10
```

Reliability:
- The orchestrator retries each sensor with exponential backoff to handle transient API timeouts (URLhaus, DShield, VT, SPUR).
- For large backfills, run processing off-hours and generate ES reports afterwards.

## Refreshing Cache and Recent Reports

Use `refresh_cache_and_reports.py` to refresh the indicator cache and reindex recent daily/weekly/monthly reports within their hot windows.

Examples:
```bash
# Refresh indicators and reports using defaults (daily 7d, weekly 30d, monthly 90d)
python refresh_cache_and_reports.py --db /mnt/dshield/data/db/cowrieprocessor.sqlite \
  --vtapi $VT_API --email you@example.com --urlhausapi $URLHAUS_API --spurapi $SPUR_API

# Only refresh indicators, no reports
python refresh_cache_and_reports.py --db /mnt/dshield/data/db/cowrieprocessor.sqlite --refresh-reports none \
  --vtapi $VT_API --email you@example.com --urlhausapi $URLHAUS_API --spurapi $SPUR_API

# Only refresh daily reports for last 7 days
python refresh_cache_and_reports.py --db /mnt/dshield/data/db/cowrieprocessor.sqlite --refresh-indicators none --refresh-reports daily
```

Notes:
- VT unknown hashes are rechecked sooner (default 12 hours) via `--hash-unknown-ttl-hours`.
- IP lookups default TTL is 12 hours; hashes default 30 days.
- Rate limits are enforced per service; adjust via flags.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the BSD 4-Clause License - see the LICENSE file for details.

This is a fork of the original project by Jessie Lagrew (https://github.com/jslagrew/cowrieprocessor). The original author's work is not covered by this license. This license only applies to modifications made by Steven Peterson.

# cowrieprocessor
The initial purpose of this application is helps simplify command input and file download data from DShield Honeypots (https://github.com/DShield-ISC/dshield). This Python applications is designed to process and summarize Cowrie logs (https://github.com/cowrie/cowrie). 

![Snag_1690ca6](https://user-images.githubusercontent.com/82918323/169907140-5a53eb8d-26ae-4fa5-82a2-2bf7782311fa.png)

**Prerequisites**

The script requires the Dropbox python module to be installed, even if not being used. To install the necessary module(s):

```
sudo apt-get install python3-dropbox
```

**Using the script - arguments**

By default, the script will look for any Cowrie JSON logs in the /srv/cowrie/var/log/cowrie path (current default for DShield honeypot if setting is enabled to locally store these files). At least one argument to search for relevant data is needed and all other arguments are optional, but may allow for additional data enrichment. 

- Required Search Term (one required)
  - --download <hash / file name) --> hash of file downloaded or otherwise created by honeypot (matches file download names in /srv/cowrie/var/lib/cowrie/downloads)
  - --ttyfile <file name> --> file name of a tty file in /srv/cowrie/var/lib/cowrie/tty/
  - --session <cowrie session number> --> session number that ties cowrie logs for a session together (found in logs)
  - --summarizedays <number of days> --> Outline all attacks and summarize for period of days specified. For example, a value of '1' will reivew only attacks from teh current day. 
    - This will create two different report text files within the destination folder. One will be the summary for every attack seen in that time period. Another file will contain only attacks that appeared more unique (low or absent virustotal hit count for malware or less than 5 instances of attacks comprised of the same number of commands executed during the attack.  
- Optional Search Term
  - --vtapi <VT API Key> --> VirusTotal API Key to enrich data with VT (will also download a local copy in working path with full JSON output)
  - --urlhausapi <URLhaus API Key> --> URLhaus API key for authenticated URLhaus lookups; if omitted, URLhaus tags are skipped
  - --email <email address> --> Your email address, which will be used to register query with DShield when querying for additional IP address data
  - --logpath <path to cowrie JSON logs> --> Enter an alernate path where cowrie logs may be stored
  - --dbxapi <Dropbox API Key> --> If included, summary data text reports will be uploaded to Dropbox account within 'cowriesummaries' folder
  - --dbxkey <Dropbox access token> --> short-lived API access key for Dropbox account
  - --dbxsecret <Dropbox access secret> --> secret used with associated short-lived API access key
  - --dbxrefreshtoken <Dropbox refresh token> --> refresh token used to get new short-lived API access key
  - --spurapi <SPUR.us API key> --> If included, IP address data will be enriched with SPUR.us data for summary, upload and download data

**Locally created files**

(script working path)/cowrieprocessor.sqlite - SQLite database with attack summary data that's been processed
  
(script working path)/\<datetime processor run\>_\<summary request\>_report.txt - summary of all attacks during requested timespan
  
(script working path)/\<datetime processor run\>\_abnormal\_\<summary request\>_report.txt - summary of unusual attacks during requested timespan
  
(script working path)/\<datetime processor run\>/(filehash) - VirusTotal results for filehash in JSON format (searhed by file hash)

(script working path)/\<datetime processor run\>/uh_(ipaddress) - URLhaus locally cached lookup results in JSON format (searched by IP)

(script working path)/\<datetime processor run\>/files_(filehash) - VirusTotal response for files uploaded to VirusTotal
  
![Snag_29dea69c](https://user-images.githubusercontent.com/82918323/185350726-4b84a14f-bbca-4e23-ab50-85fc14973049.png)
  
This data is currently stored for troubleshooting and potential analysis in the future. Not all data received from URLHaus or VirusTotal is found in the summarized data and this raw JSON data can be reviewed for additional context. 
  
**Abnormal/unusual Attack Reports**

When performing summary reviews of data, the script will also try to summarize the attacks and highlight any attack sessions that meet the following criteria
  - Unusual number of commands (when comparing against other attacks during the summary time period)
  - Malware submitted that is a recent additional to VirusTotal
  
![Snag_1684520](https://user-images.githubusercontent.com/82918323/169907013-e4235d4a-022b-43e3-addd-2538394dae93.png)

**Dropbox Upload**

Uploading to Dropbox required creating a Dropbox app associated with an account. Additional information on how to do this can be found within [Dropbox documentation](https://www.dropbox.com/developers/reference/getting-started#app%20console). 

![Snag_29f91fd4](https://user-images.githubusercontent.com/82918323/185356936-fe9cb10f-9158-480e-a7c0-bb2782881254.png)

# Command Examples

```
python3 process_cowrie.py --email <my email address> --vtapi <vt api key> --summarizedays 2
```

_Will output a summary of the last two days of attacks (today and yesterday)._

```
python3 process_cowrie.py --email <my email address> --vtapi <vt api key> --downloadfile a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2
```
  
_Will output attacks seen with the file hash given._

```
python3 process_cowrie.py --email <my email address> --vtapi <vt api key> --dbxapi <dropbox api key> --summarizedays 2
```
  
_Will process the last two days of cowrie data, enrich with URLHaus and VirusTotal data and upload to Dropbox using the Access Token (short-term API for testing)._

```
python3 process_cowrie.py --email <my email address> --vtapi <vt api key> --dbxkey <dropbox access token> --dbxsecret <dropbox secret> --dbxrefreshtoken <dropbox refresh token> --summarizedays 2
```
  
_Will process the last two days of cowrie data, enrich with URLHaus and VirusTotal data and upload to Dropbox using OAuth workflow and Refresh Token for full automation._
