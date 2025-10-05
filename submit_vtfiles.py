import os
import json
import argparse
import requests
import time
import hashlib

parser = argparse.ArgumentParser(description='Virus Total file submission options')
parser.add_argument('--filepath', dest='filepath', type=str, help='Path of a specific file to submit')
parser.add_argument('--folderpath', dest='folderpath', type=str, help='Folder ocation of files to process for submission', default='/srv/cowrie/var/lib/cowrie/downloads/')
parser.add_argument('--vtapi', dest='vtapi', type=str, help='VirusTotal API key (required for VT data lookup)')

args = parser.parse_args()

filepath = args.filepath
folderpath = args.folderpath
vtapi = args.vtapi

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
    print(each_file)
    vt_filescan(each_file)

#vt_filescan("58458d88aeb274ebd87a2cc4dad0b64f3c38c8951a287b3b31c1f99c8240d38e")
