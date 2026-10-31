from gc import collect
import json
from operator import contains
import os
import requests
from requests.exceptions import ReadTimeout
from os.path import exists
import time
import re
import datetime
import argparse
from pathlib import Path
import collections
import dropbox
import sqlite3
import logging
import sys
import socket

logging_fhandler = logging.FileHandler("cowrieprocessor.err", encoding="utf-8")
logging.root.addHandler(logging_fhandler)
basic_with_time_format = '%(asctime)s:%(levelname)s:%(name)s:%(filename)s:%(funcName)s:%(message)s'
logging_fhandler.setFormatter(logging.Formatter(basic_with_time_format))
logging_fhandler.setLevel(logging.ERROR)

stdout_handler = logging.StreamHandler(stream = sys.stdout)
stdout_handler.setFormatter(logging.Formatter(basic_with_time_format))
stdout_handler.setLevel(logging.DEBUG)

logging.root.addHandler(logging_fhandler)
logging.root.addHandler(stdout_handler)
logging.root.setLevel(logging.DEBUG)

date = datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")

def parse_cowrie_timestamp(timestamp_str):
    """
    Parse a Cowrie JSON log timestamp into a naive UTC datetime.

    Cowrie normally logs timestamps in UTC ending in "Z", e.g.:
        2026-07-21T14:40:29.318984Z
    but depending on configuration/timezone it may instead include an
    explicit UTC offset, e.g.:
        2026-07-21T14:40:29.318984-0500

    This normalizes either form to a naive datetime in UTC so downstream
    epoch-time math (which assumes UTC) continues to work correctly.
    """
    if timestamp_str.endswith("Z"):
        return datetime.datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        # Has an explicit offset instead of "Z" (e.g. -0500, +0200)
        aware_time = datetime.datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f%z")
        utc_time = aware_time.astimezone(datetime.timezone.utc)
        return utc_time.replace(tzinfo=None)

parser = argparse.ArgumentParser(description='DShield Honeypot Cowrie Data Identifiers')
parser.add_argument('--logpath', dest='logpath', type=str, help='Path of cowrie json log files', default='/srv/cowrie/var/log/cowrie')
parser.add_argument('--ttyfile', dest='ttyfile', type=str, help='Name of TTY associated TTY log file')
parser.add_argument('--downloadfile', dest='downloadfile', type=str, help='Name of downloaded file (matches file SHA-256 hash)')
parser.add_argument('--session', dest='session', type=str, help='Cowrie session number')
parser.add_argument('--vtapi', dest='vtapi', type=str, help='VirusTotal API key (required for VT data lookup)')
parser.add_argument('--email', dest='email', type=str, help='Your email address (required for DShield IP lookup)')
parser.add_argument('--summarizedays', dest='summarizedays', type=str, help='Will summarize all attacks in the give number of days')
parser.add_argument('--dbxapi', dest='dbxapi', type=str, help='Dropbox access token for use with Dropbox upload of summary text files')
parser.add_argument('--dbxkey', dest='dbxkey', type=str, help='Dropbox app key to be used to get new short-lived API access key')
parser.add_argument('--dbxsecret', dest='dbxsecret', type=str, help='Dropbox app secret to be used to get new short-lived API access key')
parser.add_argument('--dbxrefreshtoken', dest='dbxrefreshtoken', type=str, help='Dropbox refresh token to be used to get new short-lived API access key')
parser.add_argument('--spurapi', dest='spurapi', type=str, help='SPUR.us API key to be used for SPUR.us data encrichment')
parser.add_argument('--urlhausapi', dest='urlhausapi', type=str, help='urlhaus-api.abuse.ch API key to be used for URLhaus data encrichment')
parser.add_argument('--accumulate', dest='accumulate', action='store_true',
                    help='Suppress per-session output during processing; write all text reports and '
                         'SQLite data only at the end. Prints full paths of all files created/updated.')
parser.add_argument('--sourcefile', dest='sourcefile', type=str, default=None,
                    help='Path to the SQLite database file to read from and write to. '
                         'Defaults to ../cowrieprocessor.sqlite relative to the run directory.')

args = parser.parse_args()

log_location = args.logpath
tty_file = args.ttyfile
download_file = args.downloadfile
session_id = args.session
vtapi = args.vtapi
email = args.email
summarizedays = args.summarizedays
dbxapi = args.dbxapi
dbxkey = args.dbxkey
dbxsecret = args.dbxsecret
dbxrefreshtoken = args.dbxrefreshtoken
spurapi = args.spurapi
urlhausapi = args.urlhausapi
accumulate = args.accumulate
sourcefile = str(Path(args.sourcefile).resolve()) if args.sourcefile else None
log_location = str(Path(log_location).resolve())

# In accumulate mode, suppress DEBUG-level messages on stdout so only file-processing
# progress lines and warnings/errors are shown during the data collection phase.
if accumulate:
    stdout_handler.setLevel(logging.INFO)

#string prepended to filename for report summaries
#may want a '_' at the start of this string for readability
hostname = socket.gethostname()
filename_prepend = f"_{hostname}"

os.mkdir(date)
os.chdir(date)

attack_count = 0
number_of_commands = []
vt_classifications = []
vt_recent_submissions = set()
abnormal_attacks = set()
uncommon_command_counts = set()

# Collect all session IDs seen across files for post-processing abnormal attack analysis
all_session_ids = set()

# Accumulate mode: text output buffers
accumulated_standard_strings = []
accumulated_abnormal_strings = []

file_list = sorted(Path(log_location).iterdir(), key=os.path.getmtime)

list_of_files = []

# Match any file containing "cowrie.json" rather than any ".json" file
for each_file in file_list:
    if "cowrie.json" in each_file.name:
        list_of_files.append(each_file.name)

if not list_of_files:
    raise RuntimeError(f"No cowrie.json log files found in {log_location}")

# ---------------------------------------------------------------------------
# SQLite connection — used only for initial load and final bulk flush.
# All reads/writes during processing use in-memory dictionaries and sets.
# ---------------------------------------------------------------------------
# Use the user-supplied --sourcefile path if given; otherwise fall back to the
# default path one level above the run directory (preserves original behaviour).
DB_PATH = sourcefile if sourcefile is not None else '../cowrieprocessor.sqlite'
con = sqlite3.connect(DB_PATH)

# Column definitions for each table and for pre-existing database upgrades.
SESSIONS_COLS = [
    'session', 'session_duration', 'protocol', 'username', 'password', 'timestamp',
    'source_ip', 'urlhaus_tag', 'asname', 'ascountry',
    'spur_asn', 'spur_asn_organization', 'spur_organization', 'spur_infrastructure',
    'spur_client_behaviors', 'spur_client_proxies', 'spur_client_types', 'spur_client_count',
    'spur_client_concentration', 'spur_client_countries', 'spur_geospread', 'spur_risks',
    'spur_services', 'spur_location', 'spur_tunnel_anonymous', 'spur_tunnel_entries',
    'spur_tunnel_operator', 'spur_tunnel_type', 'total_commands', 'added',
]
COMMANDS_COLS = ['session', 'command', 'timestamp', 'added']
FILES_PROCESSED_COLS = ['filename', 'mtime', 'ctime', 'file_size', 'last_processed']
FILES_COLS = [
    'session', 'download_url', 'hash', 'file_path',
    'vt_description', 'vt_threat_classification', 'vt_first_submission', 'vt_hits',
    'src_ip', 'urlhaus_tag', 'asname', 'ascountry',
    'spur_asn', 'spur_asn_organization', 'spur_organization', 'spur_infrastructure',
    'spur_client_behaviors', 'spur_client_proxies', 'spur_client_types', 'spur_client_count',
    'spur_client_concentration', 'spur_client_countries', 'spur_geospread', 'spur_risks',
    'spur_services', 'spur_location', 'spur_tunnel_anonymous', 'spur_tunnel_entries',
    'spur_tunnel_operator', 'spur_tunnel_type', 'transfer_method', 'added',
]


def initialize_database():
    """
    Ensure all three tables exist in the SQLite file with the full column set,
    then load their keys into memory. Any missing columns (upgrade path
    for pre-existing databases) are added before the load.
    """
    logging.info("Database initializing...")
    cur = con.cursor()

    # Create tables if they don't exist yet
    cur.execute('''CREATE TABLE IF NOT EXISTS sessions(
        session text NOT NULL PRIMARY KEY, session_duration int, protocol text, username text, password text,
        timestamp int, source_ip text, urlhaus_tag text, asname text, ascountry text,
        spur_asn text, spur_asn_organization text, spur_organization text,
        spur_infrastructure text, spur_client_behaviors text, spur_client_proxies text,
        spur_client_types text, spur_client_count text, spur_client_concentration text,
        spur_client_countries text, spur_geospread text, spur_risks text, spur_services text,
        spur_location text, spur_tunnel_anonymous text, spur_tunnel_entries text,
        spur_tunnel_operator text, spur_tunnel_type text, total_commands int, added int)''')

    cur.execute('''CREATE TABLE IF NOT EXISTS commands(
        session text, command text, timestamp int, added int)''')

    cur.execute('''CREATE TABLE IF NOT EXISTS files(
        session text, download_url text, hash text, file_path text,
        vt_description text, vt_threat_classification text, vt_first_submission int,
        vt_hits int, src_ip text, urlhaus_tag text, asname text, ascountry text,
        spur_asn text, spur_asn_organization text, spur_organization text,
        spur_infrastructure text, spur_client_behaviors text, spur_client_proxies text,
        spur_client_types text, spur_client_count text, spur_client_concentration text,
        spur_client_countries text, spur_geospread text, spur_risks text, spur_services text,
        spur_location text, spur_tunnel_anonymous text, spur_tunnel_entries text,
        spur_tunnel_operator text, spur_tunnel_type text, transfer_method text, added int)''')

    # files_processed tracks which cowrie log files have been processed in accumulate mode.
    # filename       : basename of the log file (e.g. "cowrie.json.2024-01-01")
    # mtime          : last-modified timestamp at processing time (float epoch seconds)
    # ctime          : creation/inode-change timestamp at processing time (float epoch seconds)
    # last_processed : wall-clock time this run processed the file (float epoch seconds)
    cur.execute('''CREATE TABLE IF NOT EXISTS files_processed(
        filename text PRIMARY KEY,
        mtime real,
        ctime real,
        file_size integer,
        last_processed real)''')
    # Add file_size to pre-existing files_processed tables that predate this column
    try:
        cur.execute("ALTER TABLE files_processed ADD file_size integer")
        con.commit()
    except Exception:
        pass  # column already exists
    con.commit()

    # Add any columns missing from pre-existing databases (ALTER TABLE is idempotent via try/except)
    upgrade_cols = {
        'sessions': [c for c in SESSIONS_COLS if c not in ('session', 'total_commands', 'added')],
        'files':    [c for c in FILES_COLS    if c not in ('session', 'hash', 'file_path', 'added')],
    }
    for table, cols in upgrade_cols.items():
        for col in cols:
            try:
                cur.execute(f"ALTER TABLE {table} ADD {col} text")
                con.commit()
            except Exception:
                pass  # column already exists

    # These constraints also upgrade databases written by older versions, whose
    # pandas replace operation removed their indexes and primary key.
    if cur.execute('SELECT 1 FROM sessions WHERE session IS NULL LIMIT 1').fetchone():
        raise RuntimeError(f'sessions contains a missing session ID: {DB_PATH}')
    session_has_pk = any(row[5] for row in cur.execute('PRAGMA table_info(sessions)'))
    for name, table, columns in (
        ('ux_sessions_session', 'sessions', 'session'),
        ('ux_commands_event', 'commands', 'session, command, timestamp'),
        ('ux_files_transfer', 'files', 'session, hash, file_path'),
        ('ux_files_processed_filename', 'files_processed', 'filename'),
    ):
        if table == 'sessions' and session_has_pk:
            continue
        try:
            cur.execute(f'CREATE UNIQUE INDEX IF NOT EXISTS {name} ON {table} ({columns})')
        except sqlite3.IntegrityError as exc:
            raise RuntimeError(
                f'{table} contains duplicate {columns} keys; preserve and review '
                f'the database before rerunning: {DB_PATH}'
            ) from exc
    con.commit()

    # Load existing keys from each table into plain Python sets/dicts for O(1)
    # duplicate checking during processing.
    global _sessions_keys, _commands_keys, _files_keys
    global _sessions_rows, _commands_rows, _files_rows

    def _load_keys(table):
        try:
            cur.execute(f"SELECT * FROM {table}")
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in rows]
        except Exception:
            return []

    # Existing rows loaded as plain dicts — held only for dedup key extraction,
    # not iterated during processing.
    existing_sessions = _load_keys('sessions')
    existing_commands = _load_keys('commands')
    existing_files    = _load_keys('files')

    # Dedup key sets: O(1) membership checks throughout processing
    _sessions_keys = {r['session']: (r['timestamp'], r['source_ip'])
                      for r in existing_sessions}
    _commands_keys = {(r['session'], r['command'], r['timestamp']) for r in existing_commands}
    _files_keys    = {(r['session'], r['hash'], r['file_path']) for r in existing_files}

    # Load files_processed keys: filename -> (mtime, ctime) for fast lookup
    global _files_processed_keys, _files_processed_rows
    existing_fp = _load_keys('files_processed')
    # Map filename -> (mtime, ctime) so we can detect modification changes
    _files_processed_keys = {r['filename']: (r['mtime'], r['ctime']) for r in existing_fp}
    _files_processed_rows = {}  # filename -> dict of updated/new rows this run

    # New rows accumulated during this run as plain dicts.
    # files rows use (session, hash) as a mutable update key.
    _sessions_rows = []   # list of dicts
    _commands_rows = []   # list of dicts
    _files_rows    = {}   # (session, hash) -> dict  (supports in-place updates)


def flush_to_sqlite():
    """Append new rows atomically, preserving schema and unique indexes."""
    logging.info("Flushing new rows to SQLite...")

    def insert_rows(table, cols, rows):
        if not rows:
            return
        columns = ', '.join(f'"{col}"' for col in cols)
        placeholders = ', '.join('?' for _ in cols)
        con.executemany(
            f'INSERT INTO "{table}" ({columns}) VALUES ({placeholders})',
            (tuple(row.get(col) for col in cols) for row in rows),
        )

    with con:
        insert_rows('sessions', SESSIONS_COLS, _sessions_rows)
        insert_rows('commands', COMMANDS_COLS, _commands_rows)
        insert_rows('files', FILES_COLS, _files_rows.values())
        con.executemany(
            'INSERT INTO files_processed (filename, mtime, ctime, file_size, last_processed) '
            'VALUES (?, ?, ?, ?, ?) ON CONFLICT(filename) DO UPDATE SET '
            'mtime=excluded.mtime, ctime=excluded.ctime, '
            'file_size=excluded.file_size, last_processed=excluded.last_processed',
            (tuple(row.get(col) for col in FILES_PROCESSED_COLS)
             for row in _files_processed_rows.values()),
        )

    logging.info("Flush complete.")


# ---------------------------------------------------------------------------
# In-memory record helpers — pure Python, zero pandas during processing
# ---------------------------------------------------------------------------

def df_session_exists(session, epoch_time, source_ip=None):
    if session not in _sessions_keys:
        return False
    stored_time, stored_ip = _sessions_keys[session]
    if (stored_time is not None and float(stored_time) != float(epoch_time)) or (
            source_ip is not None and stored_ip is not None and stored_ip != source_ip):
        raise RuntimeError(
            f'Conflicting data for session ID {session} in {DB_PATH}; '
            'review the source logs before rerunning'
        )
    return True


def df_insert_session(row_dict):
    """Append a new session row to the accumulation list."""
    row = {col: row_dict.get(col, None) for col in SESSIONS_COLS}
    if not row['session']:
        raise ValueError('Cowrie session ID is missing')
    _sessions_rows.append(row)
    _sessions_keys[row['session']] = (row['timestamp'], row['source_ip'])


def df_command_exists(session, command, epoch_time):
    return (session, command, epoch_time) in _commands_keys


def df_insert_command(session, command, epoch_time):
    """Append a new command row to the accumulation list."""
    _commands_rows.append({
        'session': session, 'command': command,
        'timestamp': epoch_time, 'added': time.time()
    })
    _commands_keys.add((session, command, epoch_time))


def df_file_exists(session, hash_val, file_path):
    return (session, hash_val, file_path) in _files_keys


def df_insert_file(session, download_url, hash_val, file_path):
    """Insert a new file row into the accumulation dict (keyed for easy updates)."""
    row = {col: None for col in FILES_COLS}
    row.update({'session': session, 'download_url': download_url,
                'hash': hash_val, 'file_path': file_path})
    _files_rows[(session, hash_val)] = row
    _files_keys.add((session, hash_val, file_path))


def df_update_file(session, hash_val, updates: dict):
    """Apply column updates to a file row staged this run."""
    key = (session, hash_val)
    if key in _files_rows:
        _files_rows[key].update(updates)


# ---------------------------------------------------------------------------
# files_processed helpers — accumulate mode only
# ---------------------------------------------------------------------------

def fp_should_process(filename, current_mtime):
    """
    Return True if the file should be processed this run:
      - It has never been seen before (not in files_processed table), OR
      - Its mtime has changed since the last time it was processed.
    """
    if filename not in _files_processed_keys:
        return True  # never seen
    stored_mtime, _ = _files_processed_keys[filename]
    return stored_mtime != current_mtime  # mtime changed → reprocess


def fp_record_file(filename, mtime, ctime, file_size):
    """
    Stage a files_processed row (insert or update) for flushing at the end.
    Also updates the in-memory key so duplicate calls within a run are safe.
    """
    _files_processed_rows[filename] = {
        'filename':       filename,
        'mtime':          mtime,
        'ctime':          ctime,
        'file_size':      file_size,
        'last_processed': time.time(),
    }
    _files_processed_keys[filename] = (mtime, ctime)


# ---------------------------------------------------------------------------
# Original helper functions (unchanged logic, DB calls replaced with DF ops)
# ---------------------------------------------------------------------------

def get_connected_sessions(data):
    logging.debug("Extracting unique sessions...")
    sessions = set()
    for each_entry in data:
        if each_entry['eventid'] == "cowrie.login.success":
            sessions.add(each_entry['session'])
    return sessions

def get_session_id(data, type, match):
    logging.debug("Extracting unique sessions")
    sessions = set()
    if type == "tty":
        for each_entry in data:
            if "ttylog" in each_entry:
                if each_entry['ttylog'] == ("var/lib/cowrie/tty/" + match):
                    sessions.add(each_entry['session'])
    elif type == "download":
        for each_entry in data:
            if "shasum" in each_entry:
                if each_entry['shasum'] == match:
                    sessions.add(each_entry['session'])
    elif type == "all":
        for each_entry in data:
            if "shasum" in each_entry and "src_ip" in each_entry:
                sessions.add(each_entry['session'])
            if "ttylog" in each_entry and "src_ip" in each_entry:
                sessions.add(each_entry['session'])
        # Fall back to login.success sessions if no shasum/ttylog entries exist
        # (newer Cowrie logs may not have interactive sessions or file downloads)
        if not sessions:
            logging.debug("No shasum/ttylog sessions found; falling back to login.success sessions")
            for each_entry in data:
                if each_entry.get('eventid') == "cowrie.login.success":
                    sessions.add(each_entry['session'])
    return sessions

def get_session_duration(session, data):
    logging.debug("Getting session durations...")
    duration = ""
    for each_entry in data:
        if each_entry.get('session') == session and each_entry.get('eventid') == "cowrie.session.closed":
            value = each_entry.get('duration')
            if value is not None and value != "":
                duration = value
    if duration != "":
        return duration

    timestamps = []
    for each_entry in data:
        if each_entry.get('session') != session:
            continue
        timestamp = each_entry.get('timestamp')
        if timestamp:
            try:
                timestamps.append(parse_cowrie_timestamp(timestamp))
            except (TypeError, ValueError, AttributeError):
                logging.warning("Session %s has an invalid timestamp: %r", session, timestamp)
    if len(timestamps) >= 2:
        duration = (max(timestamps) - min(timestamps)).total_seconds()
        logging.warning("Session %s has no close-event duration; calculated %.6f seconds from event timestamps", session, duration)
        return duration
    logging.warning("Session %s has no close-event duration and fewer than two valid timestamps; duration unknown", session)
    return ""

def get_protocol_login(session, data):
    logging.debug("Getting protocol from session connection...")
    for each_entry in data:
        if each_entry['session'] == session:
            if each_entry['eventid'] == "cowrie.session.connect":
                return each_entry['protocol']

def get_login_data(session, data):
    for each_entry in data:
        if each_entry['session'] == session:
            if each_entry['eventid'] == "cowrie.login.success":
                return each_entry['username'], each_entry['password'], each_entry['timestamp'], each_entry['src_ip']

def get_command_total(session, data):
    count = 0
    for each_entry in data:
        if each_entry['session'] == session:
            if "cowrie.command." in each_entry['eventid']:
                count += 1
    return count

def get_file_download(session, data):
    url = ""
    download_ip = ""
    shasum = ""
    destfile = ""
    returndata = []
    for each_entry in data:
        if each_entry['session'] == session:
            if each_entry['eventid'] == "cowrie.session.file_download":
                if "url" in each_entry:
                    url = each_entry['url'].replace(".", "[.]").replace("://", "[://]")
                    try:
                        download_ip = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", each_entry['url'])[0]
                    except:
                        logging.info(f"Failure grabbing IP address from: '{each_entry['url']}'.")
                        try:
                            download_ip = re.findall(r":\/\/(.*?)(?:\/|$)", each_entry['url'])[0]
                        except:
                            logging.error(f"Failure grabbing domain from: '{each_entry['url']}'.")
                if "shasum" in each_entry:
                    shasum = each_entry['shasum']
                if "destfile" in each_entry:
                    destfile = each_entry['destfile']
                returndata.append([url, shasum, download_ip, destfile])
    return returndata

def get_file_upload(session, data):
    url = ""
    upload_ip = ""
    shasum = ""
    destfile = ""
    returndata = []
    for each_entry in data:
        if each_entry['session'] == session:
            if each_entry['eventid'] == "cowrie.session.file_upload":
                if "url" in each_entry:
                    url = each_entry['url'].replace(".", "[.]").replace("://", "[://]")
                    try:
                        upload_ip = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", each_entry['url'])[0]
                    except:
                        upload_ip = re.findall(r"\:\/\/(.*?)\/", each_entry['url'])[0]
                if "shasum" in each_entry:
                    shasum = each_entry['shasum']
                if "filename" in each_entry:
                    destfile = each_entry['filename']
                returndata.append([url, shasum, upload_ip, destfile])
    return returndata

def vt_query(hash):
    vt_session.headers = {'X-Apikey': vtapi}
    url = "https://www.virustotal.com/api/v3/files/" + hash
    response = vt_session.get(url)
    json_response = json.loads(response.text)
    file = open(hash, 'w')
    file.write(response.text)
    file.close()

def vt_filescan(hash):
    headers = {'X-Apikey': vtapi}
    url = "https://www.virustotal.com/api/v3/files"
    with open('/srv/cowrie/var/lib/cowrie/downloads/' + hash, 'rb') as file:
        files = {'file': ('/srv/cowrie/var/lib/cowrie/downloads/' + hash, file)}
        response = requests.post(url, headers=headers, files=files)
    json_response = json.loads(response.text)
    file = open("files_" + hash, 'w')
    file.write(response.text)
    file.close()

def fetch_url_with_retries(url, headers, max_retries=2, timeout=5):
    for attempt in range(max_retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            return response
        except ReadTimeout as e:
            logging.error(f"Read Timeout on attempt {attempt + 1}. Retrying...")
            if attempt == max_retries:
                logging.error(f"Max retries reached for URL: '{url}'. Sleeping two seconds and trying again.")
                raise e
            time.sleep(2)
        except requests.exceptions.RequestException as e:
            logging.error(f"An unexpected error occurred: {e}")
            return ""
    return None

def dshield_query(ip_address):
    headers = {"User-Agent": "DShield Research Query by " + email}
    response = fetch_url_with_retries("https://www.dshield.org/api/ip/" + ip_address + "?json", headers, 4, 15)
    try:
        json_data = json.loads(response.text)
    except:
        json_data = dshield_query(ip_address)
    return json_data

def uh_query(ip_address, uh_api):
    uh_header = {'Auth-Key': uh_api}
    host = {'host': ip_address}
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    while True:
        try:
            response = uh_session.post(url, headers=uh_header, data=host)
        except Exception as e:
            print(e)
            print("Exception hit for URLHaus query")
            time.sleep(10)
            continue
        break
    file = open("uh_" + ip_address, 'w')
    file.write(response.text)
    file.close()

def read_uh_data(ip_address, urlhausapi):
    if not exists("uh_" + ip_address):
        uh_query(ip_address, urlhausapi)
    uh_data = open("uh_" + ip_address, 'r')
    file = ""
    for eachline in uh_data:
        file += eachline
    uh_data.close()
    json_data = json.loads(file)
    tags = set()
    try:
        for eachurl in json_data['urls']:
            if eachurl['tags']:
                for eachtag in eachurl['tags']:
                    tags.add(eachtag)
    except:
        return ""
    stringtags = ""
    for eachtag in tags:
        stringtags += eachtag + ", "
    return stringtags[:-2]

def read_vt_data(hash):
    hash_info = open(hash, 'r')
    file = ""
    for each_time in hash_info:
        file += each_time
    hash_info.close()
    json_data = json.loads(file)
    try:
        vt_description = json_data['data']['attributes']['type_description']
    except:
        vt_description = ""
    try:
        vt_threat_classification = json_data['data']['attributes']['popular_threat_classification']['suggested_threat_label']
    except:
        vt_threat_classification = ""
    try:
        vt_first_submission = json_data['data']['attributes']['first_submission_date']
    except:
        vt_first_submission = 0
    try:
        vt_malicious = json_data['data']['attributes']['last_analysis_stats']['malicious']
    except:
        vt_malicious = 0
    return vt_description, vt_threat_classification, vt_first_submission, vt_malicious

def spur_query(ip_address):
    spur_session.headers = {'Token': spurapi}
    url = "https://api.spur.us/v2/context/" + ip_address
    while True:
        try:
            response = spur_session.get(url)
        except:
            print("Exception hit for SPUR query")
            time.sleep(10)
            continue
        break
    json.response = json.loads(response.text)
    file = open("spur" + "_" + ip_address.replace(":", "_") + ".json", 'w', encoding="utf-8")
    file.write(response.text)
    file.close()

def read_spur_data(ip_address):
    global summary_text
    if not exists("spur" + "_" + ip_address.replace(":", "_") + ".json"):
        spur_query(ip_address)
    spur_data = open("spur" + "_" + ip_address.replace(":", "_") + ".json", 'r', encoding="utf-8")
    file = ""
    for eachline in spur_data:
        file += eachline
    spur_data.close()
    json_data = json.loads(file)

    spur_list = []
    if "as" in json_data:
        spur_list.append(json_data['as'].get('number', ""))
        spur_list.append(json_data['as'].get('organization', ""))
    else:
        spur_list += ["", ""]

    spur_list.append(json_data.get('organization', ""))
    spur_list.append(json_data.get('infrastructure', ""))

    client = json_data.get('client', {})
    spur_list.append(client.get('behaviors', ""))
    spur_list.append(client.get('proxies', ""))
    spur_list.append(client.get('types', ""))
    spur_list.append(str(client['count']) if 'count' in client else "")
    spur_list.append(client.get('concentration', ""))
    spur_list.append(client.get('countries', ""))
    spur_list.append(client.get('spread', ""))

    spur_list.append(json_data.get('risks', ""))
    spur_list.append(json_data.get('services', ""))

    loc = json_data.get('location', {})
    city    = loc.get('city', "")    + (", " if loc.get('city') else "")
    state   = loc.get('state', "")   + (", " if loc.get('state') else "")
    country = loc.get('country', "")
    spur_list.append(city + state + country)

    tunnel_anonymous = tunnel_entries = tunnel_operator = tunnel_type = ""
    if "tunnels" in json_data:
        for t in json_data['tunnels']:
            tunnel_anonymous = t.get('anonymous', "")
            tunnel_entries   = t.get('entries', "")
            tunnel_operator  = t.get('operator', "")
            tunnel_type      = t.get('type', "")
    spur_list += [tunnel_anonymous, tunnel_entries, tunnel_operator, tunnel_type]

    return spur_list


# ---------------------------------------------------------------------------
# collect_commands — uses in-memory records, no SQLite calls
# ---------------------------------------------------------------------------

def collect_commands(data, session):
    """
    Collect command text and write new commands to df_commands.
    Returns the formatted command string.
    """
    commands = ""
    for each_entry in data:
        if each_entry['session'] == session:
            if "cowrie.command.input" in each_entry['eventid']:
                commands += "# " + each_entry['input'] + "\n"
                utc_time = parse_cowrie_timestamp(each_entry['timestamp'])
                epoch_time = (utc_time - datetime.datetime(1970, 1, 1)).total_seconds()
                if df_command_exists(session, each_entry['input'], epoch_time):
                    if not accumulate:
                        print("Command data for session " + session + " was already stored within database")
                else:
                    df_insert_command(session, each_entry['input'], epoch_time)
    return commands


def get_commands(data, session):
    """Backward-compatible wrapper."""
    return collect_commands(data, session)


# ---------------------------------------------------------------------------
# process_session_info — accumulates rows before the final SQLite write
# ---------------------------------------------------------------------------

def process_session_info(data, sessions, attack_type):
    """
    Process sessions from a single file's data.

    Both modes accumulate rows in memory immediately.
    The only difference between modes is:
      - Normal mode:  prints session detail + writes report file entry per session.
      - Accumulate mode: buffers report strings; no stdout session detail.
    The final bulk SQLite flush happens once at the end of the script in both cases.
    """
    standard_strings = []
    abnormal_strings = []

    spur_fields = [
        ("SPUR ASN", 0), ("SPUR ASN Organization", 1), ("SPUR Organization", 2),
        ("SPUR Infrastructure", 3), ("SPUR Client Behaviors", 4), ("SPUR Client Proxies", 5),
        ("SPUR Client Types", 6), ("SPUR Client Count", 7), ("SPUR Client Concentration", 8),
        ("SPUR Client Countries", 9), ("SPUR Client Geo-spread", 10), ("SPUR Risks", 11),
        ("SPUR Services", 12), ("SPUR Location", 13), ("SPUR Anonymous Tunnel", 14),
        ("SPUR Tunnel Entries", 15), ("SPUR Tunnel Operator", 16), ("SPUR Tunnel Type", 17),
    ]

    for session in sessions:
        global attack_count
        attack_count += 1
        protocol = get_protocol_login(session, data)
        session_duration = get_session_duration(session, data)

        try:
            username, password, timestamp, src_ip = get_login_data(session, data)
        except:
            continue

        command_count = get_command_total(session, data)
        if not accumulate:
            print("Command Count: " + str(command_count))
        number_of_commands.append(command_count)

        downloaddata = get_file_download(session, data)
        uploaddata   = get_file_upload(session, data)

        attackstring  = "{:>30s}  {:50s}".format("Session", str(session)) + "\n"
        duration_label = str(session_duration) + " seconds" if session_duration != "" else "unknown"
        attackstring += "{:>30s}  {:50s}".format("Session Duration", duration_label) + "\n"
        attackstring += "{:>30s}  {:50s}".format("Protocol", str(protocol)) + "\n"
        attackstring += "{:>30s}  {:50s}".format("Username", str(username)) + "\n"
        attackstring += "{:>30s}  {:50s}".format("Password", str(password)) + "\n"
        attackstring += "{:>30s}  {:50s}".format("Timestamp", str(timestamp)) + "\n"
        attackstring += "{:>30s}  {:50s}".format("Source IP Address", str(src_ip)) + "\n"
        if urlhausapi is not None:
            attackstring += "{:>30s}  {:50s}".format("URLhaus IP Tags", str(read_uh_data(src_ip, urlhausapi))) + "\n"

        json_data = None
        spur_session_data = None

        if email:
            json_data = dshield_query(src_ip)
            attackstring += "{:>30s}  {:50s}".format("ASNAME", json_data['ip']['asname']) + "\n"
            attackstring += "{:>30s}  {:50s}".format("ASCOUNTRY", json_data['ip']['ascountry']) + "\n"
            attackstring += "{:>30s}  {:<6d}".format("Total Commands Run", command_count) + "\n"

        if spurapi:
            spur_session_data = read_spur_data(src_ip)
            for label, idx in spur_fields:
                if spur_session_data[idx] != "":
                    attackstring += "{:>30s}  {:<50s}".format(label, str(spur_session_data[idx])) + "\n"

        # ---- Download data ----
        if len(downloaddata) > 0:
            attackstring += "\n------------------- DOWNLOAD DATA -------------------\n"
        for each_download in downloaddata:
            if each_download[1]:
                attackstring += "\n"
                attackstring += "{:>30s}  {:50s}".format("Download URL", each_download[0]) + "\n"
                attackstring += "{:>30s}  {:50s}".format("Download SHA-256 Hash", each_download[1]) + "\n"
                attackstring += "{:>30s}  {:50s}".format("Destination File", each_download[3]) + "\n"

                file_is_new = not df_file_exists(session, each_download[1], each_download[3])
                if file_is_new:
                    df_insert_file(session, each_download[0], each_download[1], each_download[3])
                elif not accumulate:
                    print("Download data for session " + session + " was already stored within database")

                if not exists(each_download[1]) and vtapi:
                    vt_query(each_download[1])
                    time.sleep(15)

                if exists(each_download[1]) and vtapi:
                    vt_description, vt_threat_classification, vt_first_submission, vt_malicious = read_vt_data(each_download[1])
                    attackstring += "{:>30s}  {:50s}".format("VT Description", vt_description) + "\n"
                    attackstring += "{:>30s}  {:50s}".format("VT Threat Classification", vt_threat_classification) + "\n"
                    if file_is_new:
                        df_update_file(session, each_download[1], {
                            'vt_description': vt_description,
                            'vt_threat_classification': vt_threat_classification,
                            'vt_first_submission': vt_first_submission,
                            'vt_hits': vt_malicious,
                            'transfer_method': 'DOWNLOAD',
                            'added': time.time(),
                        })
                    if vt_threat_classification == "":
                        vt_classifications.append("<blank>")
                    else:
                        vt_classifications.append(vt_threat_classification)
                    attackstring += "{:>30s}  {}".format("VT First Submssion", datetime.datetime.fromtimestamp(int(vt_first_submission))) + "\n"
                    if (datetime.datetime.now() - datetime.datetime.fromtimestamp(int(vt_first_submission))).days <= 5:
                        abnormal_attacks.add(session)
                        vt_recent_submissions.add(session)
                    attackstring += "{:>30s}  {:<6d}".format("VT Malicious Hits", vt_malicious) + "\n"

                if each_download[2] != "" and email:
                    if re.search('[a-zA-Z]', each_download[2]):
                        attackstring += "{:>30s}  {:50s}".format("Download Source Address", each_download[2]) + "\n"
                        if urlhausapi is not None:
                            uh_tag = read_uh_data(each_download[2], urlhausapi)
                            attackstring += "{:>30s}  {:50s}".format("URLhaus Source Tags", uh_tag) + "\n"
                            df_update_file(session, each_download[1], {'src_ip': each_download[2], 'urlhaus_tag': uh_tag})
                    else:
                        json_data_dl = dshield_query(each_download[2])
                        attackstring += "{:>30s}  {:50s}".format("Download Source Address", each_download[2]) + "\n"
                        if urlhausapi is not None:
                            attackstring += "{:>30s}  {:50s}".format("URLhaus IP Tags", read_uh_data(each_download[2], urlhausapi)) + "\n"
                        attackstring += "{:>30s}  {:50s}".format("ASNAME", json_data_dl['ip']['asname']) + "\n"
                        attackstring += "{:>30s}  {:50s}".format("ASCOUNTRY", json_data_dl['ip']['ascountry']) + "\n"

                        if spurapi:
                            spur_data = read_spur_data(src_ip)
                            for label, idx in spur_fields:
                                if spur_data[idx] != "":
                                    attackstring += "{:>30s}  {:<50s}".format(label, str(spur_data[idx])) + "\n"
                            df_update_file(session, each_download[1], {
                                'src_ip': each_download[2],
                                'urlhaus_tag': read_uh_data(each_download[2], urlhausapi) if urlhausapi is not None else "",
                                'asname': json_data_dl['ip']['asname'],
                                'ascountry': json_data_dl['ip']['ascountry'],
                                **{col: str(spur_data[i]) for i, col in enumerate([
                                    'spur_asn', 'spur_asn_organization', 'spur_organization', 'spur_infrastructure',
                                    'spur_client_behaviors', 'spur_client_proxies', 'spur_client_types', 'spur_client_count',
                                    'spur_client_concentration', 'spur_client_countries', 'spur_geospread', 'spur_risks',
                                    'spur_services', 'spur_location', 'spur_tunnel_anonymous', 'spur_tunnel_entries',
                                    'spur_tunnel_operator', 'spur_tunnel_type',
                                ])}
                            })

        # ---- Upload data ----
        if len(uploaddata) > 0:
            attackstring += "\n------------------- UPLOAD DATA -------------------\n"
        for each_upload in uploaddata:
            if each_upload[1]:
                attackstring += "\n"
                attackstring += "{:>30s}  {:50s}".format("Upload URL", each_upload[0]) + "\n"
                attackstring += "{:>30s}  {:50s}".format("Upload SHA-256 Hash", each_upload[1]) + "\n"
                attackstring += "{:>30s}  {:50s}".format("Destination File", each_upload[3]) + "\n"

                upload_is_new = not df_file_exists(session, each_upload[1], each_upload[3])
                if upload_is_new:
                    df_insert_file(session, each_upload[0], each_upload[1], each_upload[3])
                elif not accumulate:
                    print("Upload data for session " + session + " was already stored within database")

                if not exists(each_upload[1]) and vtapi:
                    vt_query(each_upload[1])
                    time.sleep(15)

                if exists(each_upload[1]) and vtapi:
                    vt_description, vt_threat_classification, vt_first_submission, vt_malicious = read_vt_data(each_upload[1])
                    attackstring += "{:>30s}  {:50s}".format("VT Description", vt_description) + "\n"
                    attackstring += "{:>30s}  {:50s}".format("VT Threat Classification", vt_threat_classification) + "\n"
                    attackstring += "{:>30s}  {}".format("VT First Submssion", datetime.datetime.fromtimestamp(int(vt_first_submission))) + "\n"
                    attackstring += "{:>30s}  {:<6d}".format("VT Malicious Hits", vt_malicious) + "\n"
                    if upload_is_new:
                        df_update_file(session, each_upload[1], {
                            'vt_description': vt_description,
                            'vt_threat_classification': vt_threat_classification,
                            'vt_first_submission': vt_first_submission,
                            'vt_hits': vt_malicious,
                            'transfer_method': 'UPLOAD',
                            'added': time.time(),
                        })

                if each_upload[2] != "" and email:
                    if re.search('[a-zA-Z]', each_upload[2]):
                        attackstring += "{:>30s}  {:50s}".format("Upload Source Address", each_upload[2]) + "\n"
                        if urlhausapi is not None:
                            uh_tag = read_uh_data(each_upload[2], urlhausapi)
                            attackstring += "{:>30s}  {:50s}".format("URLhaus IP Tags", uh_tag) + "\n"
                            df_update_file(session, each_upload[1], {'src_ip': each_upload[2], 'urlhaus_tag': uh_tag})
                    else:
                        json_data_ul = dshield_query(each_upload[2])
                        attackstring += "{:>30s}  {:50s}".format("Upload Source Address", each_upload[2]) + "\n"
                        if urlhausapi is not None:
                            attackstring += "{:>30s}  {:50s}".format("URLhaus IP Tags", read_uh_data(each_upload[2], urlhausapi)) + "\n"
                        attackstring += "{:>30s}  {:50s}".format("ASNAME", json_data_ul['ip']['asname']) + "\n"
                        attackstring += "{:>30s}  {:50s}".format("ASCOUNTRY", json_data_ul['ip']['ascountry']) + "\n"

                        if spurapi:
                            spur_data = read_spur_data(src_ip)
                            for label, idx in spur_fields:
                                if spur_data[idx] != "":
                                    attackstring += "{:>30s}  {:<50s}".format(label, str(spur_data[idx])) + "\n"
                            df_update_file(session, each_upload[1], {
                                'src_ip': each_upload[2],
                                'urlhaus_tag': read_uh_data(each_upload[2], urlhausapi) if urlhausapi is not None else "",
                                'asname': json_data_ul['ip']['asname'],
                                'ascountry': json_data_ul['ip']['ascountry'],
                                **{col: str(spur_data[i]) for i, col in enumerate([
                                    'spur_asn', 'spur_asn_organization', 'spur_organization', 'spur_infrastructure',
                                    'spur_client_behaviors', 'spur_client_proxies', 'spur_client_types', 'spur_client_count',
                                    'spur_client_concentration', 'spur_client_countries', 'spur_geospread', 'spur_risks',
                                    'spur_services', 'spur_location', 'spur_tunnel_anonymous', 'spur_tunnel_entries',
                                    'spur_tunnel_operator', 'spur_tunnel_type',
                                ])}
                            })

        # ---- Commands ----
        commands_text = collect_commands(data, session)
        attackstring += "\n////////////////// COMMANDS ATTEMPTED //////////////////\n\n"
        attackstring += commands_text + "\n"
        attackstring += "\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\n"

        # ---- Session row ----
        utc_time   = parse_cowrie_timestamp(timestamp)
        epoch_time = (utc_time - datetime.datetime(1970, 1, 1)).total_seconds()

        asname_val    = json_data['ip']['asname']    if json_data else ""
        ascountry_val = json_data['ip']['ascountry'] if json_data else ""
        urlhaus_val   = read_uh_data(src_ip, urlhausapi) if urlhausapi is not None else ""

        if df_session_exists(session, epoch_time, src_ip):
            if not accumulate:
                print("Data for session " + session + " was already stored within database")
        else:
            sess_row = {
                'session': session, 'session_duration': session_duration,
                'protocol': protocol, 'username': username, 'password': password,
                'timestamp': epoch_time, 'source_ip': src_ip,
                'urlhaus_tag': urlhaus_val, 'asname': asname_val, 'ascountry': ascountry_val,
                'total_commands': command_count, 'added': time.time(),
            }
            if spur_session_data:
                spur_col_names = [
                    'spur_asn', 'spur_asn_organization', 'spur_organization', 'spur_infrastructure',
                    'spur_client_behaviors', 'spur_client_proxies', 'spur_client_types', 'spur_client_count',
                    'spur_client_concentration', 'spur_client_countries', 'spur_geospread', 'spur_risks',
                    'spur_services', 'spur_location', 'spur_tunnel_anonymous', 'spur_tunnel_entries',
                    'spur_tunnel_operator', 'spur_tunnel_type',
                ]
                for i, col in enumerate(spur_col_names):
                    sess_row[col] = str(spur_session_data[i])
            df_insert_session(sess_row)

        # ---- Output ----
        if not accumulate:
            print(attackstring)
            if attack_type == "abnormal":
                fname = (date + "_abnormal_" + summarizedays + "-day_report.txt") if summarizedays else (date + "_abnormal_report.txt")
            else:
                fname = (date + "_" + summarizedays + "_day_report.txt") if summarizedays else (date + "_report.txt")
            with open(fname, "a", encoding="utf-8") as rf:
                rf.write(attackstring)
        else:
            if attack_type == "abnormal":
                abnormal_strings.append(attackstring)
            else:
                standard_strings.append(attackstring)

    return standard_strings, abnormal_strings


def print_session_info(data, sessions, attack_type):
    """Wrapper for normal (non-accumulate) mode."""
    process_session_info(data, sessions, attack_type)


def print_summary():
    print("\n\n{:>30s}  {:8.2f}".format("Total Sessions", len(session_data)))
    print("{:>30s}  {:8.2f}".format("Most # of Commands Run", max(command_count_data)))
    print("{:>30s}  {:8.2f}\n\n".format("Average # of Commands Run",
          sum(command_count_data) / len(command_count_data)))


# ============================================================
# Main execution
# ============================================================

initialize_database()

if len(list_of_files) == 0: quit()

if summarizedays:
    days = int(summarizedays)
    print("Days to summarize: " + str(days))
    trimmed_list = []
    i = 0
    while len(list_of_files) > 0 and i < days:
        trimmed_list.append(list_of_files.pop())
        i += 1
    list_of_files = trimmed_list

vt_session      = requests.session()
dshield_session = requests.session()
uh_session      = requests.session()
spur_session    = requests.session()

# Process one file at a time to keep only one file's log entries in memory at once.
# In accumulate mode, skip files that haven't changed since they were last processed.
for each_file in list_of_files:
    file_path = log_location + "/" + each_file
    fp = Path(log_location) / each_file
    fp_stat = fp.stat()
    current_mtime = fp_stat.st_mtime
    current_ctime = fp_stat.st_ctime
    current_size  = fp_stat.st_size

    if accumulate:
        if not fp_should_process(each_file, current_mtime):
            print("Skipping (already processed, unchanged): " + file_path)
            continue

    data = []
    with open(file_path, 'r') as f:
        print("Processing file " + file_path)
        for each_line in f:
            try:
                json_file = json.loads(each_line.replace('\0', ''))
                data.append(json_file)
            except Exception as e:
                logging.error(f"Error parsing data: {e}")
                logging.error(f"Data with error: '{each_line}'")

    if session_id:
        file_sessions = [session_id]
    elif tty_file:
        file_sessions = get_session_id(data, "tty", tty_file)
    elif download_file:
        file_sessions = get_session_id(data, "download", download_file)
    else:
        file_sessions = get_session_id(data, "all", "unnecessary")

    all_session_ids.update(file_sessions)

    if accumulate:
        std_s, abn_s = process_session_info(data, file_sessions, "standard")
        accumulated_standard_strings.extend(std_s)
        accumulated_abnormal_strings.extend(abn_s)
        # Record this file as processed (staged for flush at end of run)
        fp_record_file(each_file, current_mtime, current_ctime, current_size)
    else:
        print_session_info(data, file_sessions, "standard")

    data = []  # release memory before next file

vt_session.close()
dshield_session.close()
uh_session.close()
spur_session.close()

# ---- Post-processing: command count analysis ----
counts = collections.Counter(number_of_commands)
number_of_commands = sorted(number_of_commands, key=lambda x: -counts[x])
commands_set = set(number_of_commands)

command_number_dict = {cmd: number_of_commands.count(cmd) for cmd in commands_set}
command_number_dict = sorted(command_number_dict.items(), key=lambda x: x[1])

abnormal_command_counts = [k for k, v in command_number_dict]
abnormal_command_counts = abnormal_command_counts[0:int(len(abnormal_command_counts) * (2 / 3))]

vt_counts = collections.Counter(vt_classifications)
vt_classifications = sorted(vt_classifications, key=lambda x: -vt_counts[x])
vt_class = set(vt_classifications)

# Identify abnormal sessions from the in-memory _sessions_rows list (available in both modes).
# _sessions_rows holds all new rows accumulated this run; also check existing rows via SQLite
# for sessions that were already in the DB before this run started.
def _get_command_count_for_session(sess_id):
    """Return total_commands for a session, checking new rows first then the DB."""
    for row in _sessions_rows:
        if row['session'] == sess_id:
            return row['total_commands']
    # Fall back to SQLite for sessions that existed before this run
    cur = con.cursor()
    cur.execute("SELECT total_commands FROM sessions WHERE session=?", (sess_id,))
    row = cur.fetchone()
    return row[0] if row else None

for each_session in all_session_ids:
    cmd_count = _get_command_count_for_session(each_session)
    if cmd_count is not None:
        if cmd_count in abnormal_command_counts:
            try:
                abnormal_attacks.add(each_session)
            except:
                logging.error(f"Failure adding session for abnormal attacks {each_session}")
            try:
                uncommon_command_counts.add(each_session)
            except:
                logging.error(f"Failure adding session for uncommon commands {each_session}")

# ---- Build summary string ----
summarystring  = "{:>40s}  {:10s}".format("Total Number of Attacks:", str(attack_count)) + "\n"
summarystring += "{:>40s}  {:10s}".format("Most Common Number of Commands:",
                                           str(number_of_commands[0]) if number_of_commands else "0") + "\n"
summarystring += "\n"
summarystring += "{:>40s}  {:10s}".format("Number of Commands", "Times Seen") + "\n"
summarystring += "{:>40s}  {:10s}".format("------------------", "----------") + "\n"
for key, value in command_number_dict:
    summarystring += "{:>40s}  {:10s}".format(str(key), str(value)) + "\n"
summarystring += "\n"
summarystring += "{:>48s}".format("VT Classifications") + "\n"
summarystring += "{:>48s}".format("------------------") + "\n"
for classification in vt_class:
    summarystring += "{:>40s}  {:10s}".format(classification, str(vt_classifications.count(classification))) + "\n"
summarystring += "\n"
summarystring += "{:>60s}".format("Attacks With Uncommon Command Counts", "") + "\n"
summarystring += "{:>60s}".format("------------------------------------") + "\n"
for each_submission in uncommon_command_counts:
    summarystring += "{:>40s}  {:10s}".format("", each_submission) + "\n"
summarystring += "\n"
summarystring += "{:>60s}".format("Attacks With Recent VT First Submission") + "\n"
summarystring += "{:>60s}".format("---------------------------------------") + "\n"
for each_submission in vt_recent_submissions:
    summarystring += "{:>40s}  {:10s}".format("", each_submission) + "\n"
summarystring += "\n"
summarystring += "{:>50s}".format("Abnormal Attacks") + "\n"
summarystring += "{:>50s}".format("----------------") + "\n"
for each_attack in abnormal_attacks:
    summarystring += "{:>40s}  {:10s}".format("", each_attack) + "\n"
summarystring += "\n\n"

# ---- Determine report filenames ----
if summarizedays:
    report_filename          = date + "_" + summarizedays + "_day_report.txt"
    abnormal_report_filename = date + "_abnormal_" + summarizedays + "-day_report.txt"
else:
    report_filename          = date + "_report.txt"
    abnormal_report_filename = date + "_abnormal_report.txt"

db_path              = os.path.abspath(DB_PATH)
report_path          = os.path.abspath(report_filename)
abnormal_report_path = os.path.abspath(abnormal_report_filename)

# ---- Abnormal-attack reporting pass ----
vt_session      = requests.session()
dshield_session = requests.session()
uh_session      = requests.session()
spur_session    = requests.session()

for each_file in list_of_files:
    file_path = log_location + "/" + each_file
    data = []
    with open(file_path, 'r') as f:
        for each_line in f:
            try:
                json_file = json.loads(each_line.replace('\0', ''))
                data.append(json_file)
            except Exception as e:
                logging.error(f"Error parsing data: {e}")
                logging.error(f"Data with error: '{each_line}'")
    file_sessions = get_session_id(data, "all", "unnecessary")
    file_abnormal = abnormal_attacks.intersection(file_sessions)
    if file_abnormal:
        # process_session_info returns (standard_strings, abnormal_strings);
        # with attack_type="abnormal" the detail text is in the SECOND element.
        _, abn_s_extra = process_session_info(data, file_abnormal, "abnormal")
        if accumulate:
            accumulated_abnormal_strings.extend(abn_s_extra)
    data = []

vt_session.close()
dshield_session.close()
uh_session.close()
spur_session.close()

# ---- Write text reports ----
if not accumulate:
    with open(report_filename, "a") as rf:
        rf.write(summarystring)
    with open(abnormal_report_filename, "a") as rf:
        rf.write(summarystring)
else:
    print("\nAll files processed. Writing output files and database...")
    with open(report_filename, "a", encoding="utf-8") as rf:
        for s in accumulated_standard_strings:
            rf.write(s)
        rf.write(summarystring)
    with open(abnormal_report_filename, "a", encoding="utf-8") as rf:
        for s in accumulated_abnormal_strings:
            rf.write(s)
        rf.write(summarystring)

# ---- Append accumulated rows to SQLite (one transaction, both modes) ----
flush_to_sqlite()

if accumulate:
    print("\n--- Output files created/updated ---")
    print(f"  Report:          {report_path}")
    print(f"  Abnormal report: {abnormal_report_path}")
    print(f"  SQLite database: {db_path}")
    print("------------------------------------\n")

# ---- Optional Dropbox upload ----

# The simple dbx.files_upload() call only supports files up to 150MB.
# For anything larger (e.g. a big accumulated SQLite database), Dropbox
# requires using an upload session, uploaded in chunks.
DROPBOX_SIMPLE_UPLOAD_LIMIT = 150 * 1024 * 1024  # 150MB
DROPBOX_CHUNK_SIZE = 8 * 1024 * 1024  # 8MB per chunk

def dropbox_upload_file(dbx, local_path, dest_path):
    """
    Upload a file to Dropbox, transparently handling files larger than the
    150MB simple-upload limit via a chunked upload session.
    """
    file_size = os.path.getsize(local_path)

    if file_size <= DROPBOX_SIMPLE_UPLOAD_LIMIT:
        with open(local_path, 'rb') as f:
            dbx.files_upload(f.read(), dest_path, mode=dropbox.files.WriteMode.overwrite)
        return

    # Chunked upload for files over 150MB
    with open(local_path, 'rb') as f:
        upload_session_start_result = dbx.files_upload_session_start(f.read(DROPBOX_CHUNK_SIZE))
        cursor = dropbox.files.UploadSessionCursor(
            session_id=upload_session_start_result.session_id,
            offset=f.tell()
        )
        commit = dropbox.files.CommitInfo(path=dest_path, mode=dropbox.files.WriteMode.overwrite)

        while f.tell() < file_size:
            if (file_size - f.tell()) <= DROPBOX_CHUNK_SIZE:
                dbx.files_upload_session_finish(f.read(DROPBOX_CHUNK_SIZE), cursor, commit)
            else:
                dbx.files_upload_session_append_v2(f.read(DROPBOX_CHUNK_SIZE), cursor)
                cursor.offset = f.tell()

if dbxapi:
    dbx = dropbox.Dropbox(dbxapi)
    dropbox_upload_file(dbx, report_filename, "/" + date + filename_prepend +
                         ("_" + summarizedays + "_day" if summarizedays else "") + "_report.txt")
    dropbox_upload_file(dbx, abnormal_report_filename, "/" + date + filename_prepend + "_abnormal_" +
                         (summarizedays + "-day" if summarizedays else "") + "_report.txt")
    dropbox_upload_file(dbx, DB_PATH, "/" + date + filename_prepend + "_cowrieprocessor.sqlite")

elif dbxkey and dbxsecret and dbxrefreshtoken:
    dbx = dropbox.Dropbox(app_key=dbxkey, app_secret=dbxsecret, oauth2_refresh_token=dbxrefreshtoken)
    dropbox_upload_file(dbx, report_filename, "/" + date + filename_prepend +
                         ("_" + summarizedays + "_day" if summarizedays else "") + "_report.txt")
    dropbox_upload_file(dbx, abnormal_report_filename, "/" + date + filename_prepend + "_abnormal_" +
                         (summarizedays + "-day" if summarizedays else "") + "_report.txt")
    dropbox_upload_file(dbx, DB_PATH, "/" + date + filename_prepend + "_cowrieprocessor.sqlite")

else:
    print("No Dropbox account information supplied to allow upload")

print(summarystring)
