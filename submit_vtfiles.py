import os
import json
import argparse
import requests
import time
import hashlib
import subprocess

try:
    import magic
    HAVE_PYMAGIC = True
except ImportError:
    HAVE_PYMAGIC = False

parser = argparse.ArgumentParser(description='Virus Total file submission options')
parser.add_argument('--filepath', dest='filepath', type=str, help='Path of a specific file to submit')
parser.add_argument('--folderpath', dest='folderpath', type=str, help='Folder ocation of files to process for submission', default='/srv/cowrie/var/lib/cowrie/downloads/')
parser.add_argument('--vtapi', dest='vtapi', type=str, help='VirusTotal API key (required for VT data lookup)')
parser.add_argument('--skiplog', dest='skiplog', type=str, help='Path to log file recording files skipped due to file type', default='vtsubmissions/skipped_files.log')

args = parser.parse_args()

filepath = args.filepath
folderpath = args.folderpath
vtapi = args.vtapi
skiplog = args.skiplog

# File types that should never be submitted to VirusTotal.
# Matched against the description returned by `file`/libmagic.
SKIP_FILE_TYPE_SUBSTRINGS = [
    "OpenSSH RSA public key",
]

# Content markers that indicate a file is an authorized_keys-style artifact
# rather than a malware sample (checked as a fallback when the magic-byte
# description doesn't catch it, e.g. for oddly-formed key files).
SKIP_CONTENT_MARKERS = [
    b"ssh-rsa ",
]

def get_file_type(full_path):
    """Return a human-readable file type description, using python-magic
    if it's installed, otherwise falling back to the `file` command."""
    if HAVE_PYMAGIC:
        try:
            return magic.from_file(full_path)
        except Exception:
            pass
    try:
        output = subprocess.run(
            ["file", "--brief", full_path],
            capture_output=True, text=True, check=True
        )
        return output.stdout.strip()
    except Exception:
        return ""


def should_skip_file(full_path):
    """Check whether a file should be skipped (not submitted to VT).
    Returns (True, reason) if it should be skipped, otherwise (False, None)."""
    file_type = get_file_type(full_path)
    for marker in SKIP_FILE_TYPE_SUBSTRINGS:
        if marker in file_type:
            return True, "file type matched '{}' ({})".format(marker, file_type)

    try:
        with open(full_path, 'rb') as f:
            contents = f.read()
        for marker in SKIP_CONTENT_MARKERS:
            if marker in contents:
                return True, "file content matched marker '{}'".format(marker.decode(errors='replace'))
    except Exception:
        pass

    return False, None


def log_skip(filename, reason):
    if not os.path.exists("vtsubmissions"):
        os.mkdir("vtsubmissions")
    log_dir = os.path.dirname(skiplog)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    with open(skiplog, 'a') as f:
        f.write("{} - {} - skipped: {}\n".format(
            time.strftime("%Y-%m-%d %H:%M:%S"), filename, reason
        ))


def vt_filescan(filename):
    headers = {'X-Apikey': vtapi}
    url = "https://www.virustotal.com/api/v3/files"
    with open(folderpath + filename, 'rb') as file:
        files = {'file': (folderpath + filename, file)}
        response = requests.post(url, headers=headers, files=files)
    json_response = json.loads(response.text)
    if not os.path.exists("vtsubmissions"):
        os.mkdir("vtsubmissions")
    file = open("vtsubmissions/files_" + filename, 'w')
    file.write(response.text)
    file.close()

    filehash = sha256sum(folderpath + filename)
    headers = {
        'Content-type': 'application/json',
        'X-Apikey': vtapi}
    url = "https://www.virustotal.com/api/v3/files/" + filehash + "/comments"
    commentdata = {'data':{'type': 'comment', 'attributes': {'text': 'File submitted from a DShield Honeypot - https://github.com/DShield-ISC/dshield'}}}
    response = requests.post(url, headers=headers, data=json.dumps(commentdata))
    json_response = json.loads(response.text)
    file = open("vtsubmissions/files_comment_" + filename, 'w')
    file.write(response.text)
    file.close()


def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()

past = time.time() - ((60*60)/11) #1/11 of an hour - just under 6 minutes
result = []
for p, ds, fs in os.walk(folderpath):
    for fn in fs:
        filepath = os.path.join(p, fn)
        if os.path.getmtime(filepath) >= past:
            result.append(fn)

for each_file in result:
    full_path = os.path.join(folderpath, each_file)
    skip, reason = should_skip_file(full_path)
    if skip:
        print("Skipping {}: {}".format(each_file, reason))
        log_skip(each_file, reason)
        continue
    print(each_file)
    vt_filescan(each_file)

#vt_filescan("58458d88aeb274ebd87a2cc4dad0b64f3c38c8951a287b3b31c1f99c8240d38e")
