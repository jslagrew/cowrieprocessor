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
