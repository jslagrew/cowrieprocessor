# cowrieprocessor
The initial purpose of this application is helps simplify command input and file download data from DShield Honeypots (https://github.com/DShield-ISC/dshield). This Python applications is designed to process and summarize Cowrie logs (https://github.com/cowrie/cowrie). 

![Snag_1690ca6](https://user-images.githubusercontent.com/82918323/169907140-5a53eb8d-26ae-4fa5-82a2-2bf7782311fa.png)

![Snag_1684520](https://user-images.githubusercontent.com/82918323/169907013-e4235d4a-022b-43e3-addd-2538394dae93.png)


By default, the script will look for any Cowrie JSON logs in the /srv/cowrie/var/log/cowrie path (current default for DShield honeypot if setting is enabled to locally store these files). At least one argument to search for relevant data is needed and all other arguments are optional, but may allow for additional data enrichment. 

- Required Search Term (one required)
  - --download <hash / file name) --> hash of file downloaded or otherwise created by honeypot (matches file download names in /srv/cowrie/var/lib/cowrie/downloads)
  - --ttyfile <file name> --> file name of a tty file in /srv/cowrie/var/lib/cowrie/tty/
  - --session <cowrie session number> --> session number that ties cowrie logs for a session together (found in logs)
- Optional Search Term
  - --vtapi <VT API Key> --> VirusTotal API Key to enrich data with VT (will also download a local copy in working path with full JSON output)
  - --email <email address> --> Your email address, which will be used to register query with DShield when querying for additional IP address data
  - --path <path to cowrie JSON logs> --> Enter an alernate path where cowrie logs may be stored
  - --summarizedays <number of days> --> Outline all attacks and summarize for period of days specified. For example, a value of '1' will reivew only attacks from teh current day. 
    - This will create two different report text files within the destination folder. One will be the summary for every attack seen in that time period. Another file will contain only attacks that appeared more unique (low or absent virustotal hit count for malware or less than 5 instances of attacks comprised of the same number of commands executed during the attack.

**Locally created files**

(script working path)/\<datetime processor run\>/(filehash) - VirusTotal results for filehash in JSON format (searhed by file hash)

(script working path)/\<datetime processor run\>/uh_(ipaddress) - URLhaus locally cached lookup results in JSON format (searched by IP)

(script working path)/\<datetime processor run\>/files_(filehash) - VirusTotal response for files uploaded to VirusTotal

# Command Examples

```
python process_cowrie.py --email <my email address> --vtapi <vt api key> --summarizedays 2
```

_Will output a summary of the last two days of attacks (today and yesterday)._

```
python process_cowrie.py --email <my email address> --vtapi <vt api key> --downloadfile a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2
```
  
_Will output attacks seen with the file hash given._
