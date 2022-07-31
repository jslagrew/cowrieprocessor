import os
import json
import argparse
import requests
import time

parser = argparse.ArgumentParser(description='Virus Total file submission options')
parser.add_argument('--filepath', dest='filepath', type=str, help='Path of a specific file to submit')
parser.add_argument('--folderpath', dest='folderpath', type=str, help='Folder ocation of files to process for submission', default='/srv/cowrie/var/lib/cowrie/downloads/')
parser.add_argument('--vtapi', dest='vtapi', type=str, help='VirusTotal API key (required for VT data lookup)')

args = parser.parse_args()

filepath = args.filepath
folderpath = args.folderpath
vtapi = args.vtapi



def vt_filescan(hash):
    headers = {'X-Apikey': vtapi}
    url = "https://www.virustotal.com/api/v3/files"
    with open(folderpath + hash, 'rb') as file:
        files = {'file': (folderpath + hash, file)}
        response = requests.post(url, headers=headers, files=files)
    json_response = json.loads(response.text)
    file = open("vtsubmissions/files_" + hash, 'w')
    file.write(response.text)
    file.close()

    headers = {
        'Content-type': 'application/json',
        'X-Apikey': vtapi}
    url = "https://www.virustotal.com/api/v3/files/" + hash + "/comments"
    commentdata = {'data':{'type': 'comment', 'attributes': {'text': 'File submitted from a DShield Honeypot - https://github.com/DShield-ISC/dshield'}}}
    response = requests.post(url, headers=headers, data=json.dumps(commentdata))
    json_response = json.loads(response.text)
    file = open("vtsubmissions/files_comment_" + hash, 'w')
    file.write(response.text)
    file.close()

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
#vt_filescan("e94c45e125a530a6590210423d364fd3850dac5df64c78061a4aa913ba89b372")
