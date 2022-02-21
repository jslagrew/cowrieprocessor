# cowrieprocessor
The initial purpose of this application is helps simplify command input and file download data from DShield Honeypots (https://github.com/DShield-ISC/dshield). This Python applications is designed to process and generalize Cowrie logs (https://github.com/cowrie/cowrie). 

![image](https://user-images.githubusercontent.com/82918323/154689623-c9b8aa9e-8fbd-4d9b-b277-85f0cd68bdcc.png)

By default, the script will look for any Cowrie JSON logs in the /srv/cowrie/var/log/cowrie path (current default for DShield honeypot if setting is enabled to locally store these files). At least one argument to search for relevant data is needed and all other arguments are optional, but may allow for additional data enrichment. 

- Required Search Term (one required)
  - --download <hash / file name) --> hash of file downloaded or otherwise created by honeypot (matches file download names in /srv/cowrie/var/lib/cowrie/downloads)
  - --ttyfile <file name> --> file name of a tty file in /srv/cowrie/var/lib/cowrie/tty/
  - --session <cowrie session number> --> session number that ties cowrie logs for a session together (found in logs)
- Optional Search Term
  - --vtapi <VT API Key> --> VirusTotal API Key to enrich data with VT (will also download a local copy in working path with full JSON output)
  - --email <email address> --> Your email address, which will be used to register query with DShield when querying for additional IP address data
  - --path <path to cowrie JSON logs> --> Enter an alernate path where cowrie logs may be stored

**Locally created files**

(script working path)/(filehash) - VirusTotal results for filehash in JSON format (searhed by file hash)

(script working path)/uh_(ipaddress) - URLhaus locally cached lookup results in JSON format (searched by IP)

(script working path)/files_(filehash) - VirusTotal response for files uploaded to VirusTotal
