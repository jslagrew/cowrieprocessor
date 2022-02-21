from distutils import command
import json
from operator import contains
import os
import requests
from os.path import exists
import time
import re
import datetime
import argparse

parser = argparse.ArgumentParser(description='DShield Honeypot Cowrie Data Identifiers')
parser.add_argument('--logpath', dest='logpath', type=str, help='Path of cowrie json log files', default='/srv/cowrie/var/log/cowrie')
parser.add_argument('--ttyfile', dest='ttyfile', type=str, help='Name of TTY associated TTY log file')
parser.add_argument('--downloadfile', dest='downloadfile', type=str, help='Name of downloaded file (matches file SHA-256 hash)')
parser.add_argument('--session', dest='session', type=str, help='Cowrie session number')
parser.add_argument('--vtapi', dest='vtapi', type=str, help='VirusTotal API key (required for VT data lookup)')
parser.add_argument('--email', dest='email', type=str, help='Your email address (required for DShield IP lookup)')

args = parser.parse_args()

log_location = args.logpath
tty_file = args.ttyfile
download_file = args.downloadfile
session_id = args.session
vtapi = args.vtapi
email = args.email

data = []

file_list = os.listdir(log_location)

def get_connected_sessions(data):
    sessions = set()
    for each_entry in data:
        if each_entry['eventid'] == "cowrie.login.success": 
            sessions.add(each_entry['session'])
    return sessions

def get_session_id(data, type, match):
    sessions = set()
    if (type == "tty"):
        for each_entry in data:
            if ("ttylog" in each_entry):
                if each_entry['ttylog'] == ("var/lib/cowrie/tty/" + match): 
                    sessions.add(each_entry['session'])
    elif (type == "download"):
        for each_entry in data:
            if ("shasum" in each_entry):
                if each_entry['shasum'] == match: 
                    sessions.add(each_entry['session'])
    return sessions

def get_protocol_login(session, data):
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
                        download_ip = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",each_entry['url'])[0]
                    except:
                        download_ip = re.findall(r"http\:\/\/(.*)\/",each_entry['url'])[0]
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
                        upload_ip = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",each_entry['url'])[0]
                    except:
                        upload_ip = re.findall(r"http\:\/\/(.*)\/",each_entry['url'])[0]
                if "shasum" in each_entry:
                    shasum = each_entry['shasum']
                if "filename" in each_entry:
                    destfile = each_entry['filename']
                returndata.append([url, shasum, upload_ip, destfile])
    #vt_filescan(shasum)
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

def dshield_query(ip_address):
    headers = {"User-Agent": "DShield Research Query by " + email}
    response = requests.get("https://www.dshield.org/api/ip/" + ip_address + "?json", headers=headers)
    try:
        json_data = json.loads(response.text)
    except:
        json_data = dshield_query(ip_address)
    return json_data

def uh_query(ip_address):
    host = {'host': ip_address}
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    response = uh_session.post(url, data=host)
    json.response = json.loads(response.text)
    file = open("uh_" + ip_address, 'w')
    file.write(response.text)
    file.close()

def read_uh_data(ip_address):
    if not exists("uh_" + ip_address):
        uh_query(ip_address)
    uh_data = open("uh_" + ip_address, 'r')
    tags = ""
    file = ""
    for eachline in uh_data:
        file += eachline
    uh_data.close
    json_data = json.loads(file)
    tags = set()
    try:
        for eachurl in json_data['urls']:
            if (eachurl['tags']):
                for eachtag in eachurl['tags']:
                    tags.add(eachtag)
    except:
        return ""
    stringtags = ""
    for eachtag in tags:
        stringtags += eachtag + ", "
    return stringtags[:-2]


def read_vt_data(hash):
    hash_info = open(hash,'r')
    file = ""
    for each_time in hash_info:
        file += each_time
    hash_info.close
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


def print_session_info(data, sessions):
    for session in sessions:
        protocol = get_protocol_login(session, data)
        username, password, timestamp, src_ip = get_login_data(session, data)
        command_count = get_command_total(session, data)
        downloaddata = get_file_download(session, data)
        uploaddata = get_file_upload(session, data)

        print("\n----------------------------------------------------\n")
        print("{:>30s}  {:50s}".format("Session",session))
        print("{:>30s}  {:50s}".format("Protocol",protocol))
        print("{:>30s}  {:50s}".format("Username",username))
        print("{:>30s}  {:50s}".format("Password",password))
        print("{:>30s}  {:50s}".format("Timestamp",timestamp))
        print("{:>30s}  {:50s}".format("Source IP Address",src_ip))
        print("{:>30s}  {:50s}".format("URLhaus IP Tags",read_uh_data(src_ip)))

        if(email):
            json_data = dshield_query(src_ip)
            print("{:>30s}  {:50s}".format("ASNAME",(json_data['ip']['asname'])))
            print("{:>30s}  {:50s}".format("ASCOUNTRY",(json_data['ip']['ascountry'])))
            print("{:>30s}  {:<6d}".format("Total Commands Run",command_count))

        if len(downloaddata) > 0:
            print("\n------------------- DOWNLOAD DATA -------------------")
        for each_download in downloaddata:
            if(each_download[1]):
                print("")
                print("{:>30s}  {:50s}".format("Download URL",each_download[0]))
                print("{:>30s}  {:50s}".format("Download SHA-256 Hash",each_download[1]))
                print("{:>30s}  {:50s}".format("Destination File",each_download[3]))

                if (not(exists(each_download[1])) and vtapi):
                    vt_query(each_download[1])
                    time.sleep(15)

                if (exists(each_download[1]) and vtapi):
                    vt_description, vt_threat_classification, vt_first_submission, vt_malicious = read_vt_data(each_download[1])
                    print("{:>30s}  {:50s}".format("VT Description",(vt_description)))
                    print("{:>30s}  {:50s}".format("VT Threat Classification",(vt_threat_classification)))
                    print("{:>30s}  {}".format("VT First Submssion",(datetime.datetime.fromtimestamp(int(vt_first_submission)))))
                    print("{:>30s}  {:<6d}".format("VT Malicious Hits",(vt_malicious)))

                if (each_download[2] != "" and email):
                    if (re.search('[a-zA-Z]', each_download[2])):
                        print("{:>30s}  {:50s}".format("Download Source Address",each_download[2]))
                        print("{:>30s}  {:50s}".format("URLhaus Source Tags",read_uh_data(each_download[2])))

                    else:
                        json_data = dshield_query(each_download[2])
                        print("{:>30s}  {:50s}".format("Download Source Address",each_download[2]))
                        print("{:>30s}  {:50s}".format("URLhaus IP Tags",read_uh_data(each_download[2])))
                        print("{:>30s}  {:50s}".format("ASNAME",(json_data['ip']['asname'])))
                        print("{:>30s}  {:50s}".format("ASCOUNTRY",(json_data['ip']['ascountry'])))

        if len(uploaddata) > 0:
            print("\n------------------- UPLOAD DATA -------------------")
        for each_upload in uploaddata:
            if(each_upload[1]):
                print("")
                print("{:>30s}  {:50s}".format("Upload URL",each_upload[0]))
                print("{:>30s}  {:50s}".format("Upload SHA-256 Hash",each_upload[1]))
                print("{:>30s}  {:50s}".format("Destination File",each_upload[3]))

                if (not(exists(each_upload[1])) and vtapi):
                    vt_query(each_upload[1])
                    time.sleep(15)

                if (exists(each_upload[1]) and vtapi):
                    vt_description, vt_threat_classification, vt_first_submission, vt_malicious = read_vt_data(each_upload[1])
                    print("{:>30s}  {:50s}".format("VT Description",(vt_description)))
                    print("{:>30s}  {:50s}".format("VT Threat Classification",(vt_threat_classification)))
                    print("{:>30s}  {}".format("VT First Submssion",(datetime.datetime.fromtimestamp(int(vt_first_submission)))))
                    print("{:>30s}  {:<6d}".format("VT Malicious Hits",(vt_malicious)))

                if (each_upload[2] != "" and email):
                    if (re.search('[a-zA-Z]', each_upload[2])):
                        print("{:>30s}  {:50s}".format("Upload Source Address",each_upload[2]))
                        print("{:>30s}  {:50s}".format("URLhaus IP Tags",read_uh_data(each_upload[2])))

                    else:
                        json_data = dshield_query(each_upload[2])
                        print("{:>30s}  {:50s}".format("Upload Source Address",each_upload[2]))
                        print("{:>30s}  {:50s}".format("URLhaus IP Tags",read_uh_data(each_upload[2])))
                        print("{:>30s}  {:50s}".format("ASNAME",(json_data['ip']['asname'])))
                        print("{:>30s}  {:50s}".format("ASCOUNTRY",(json_data['ip']['ascountry'])))



        print("\n////////////////// COMMANDS ATTEMPTED //////////////////\n")
        print_commands(data, session)
        print("\n----------------------------------------------------\n")

def print_summary():
    print("\n\n{:>30s}  {:8.2f}"
        .format("Total Sessions",
        len(session_data)))

    print("{:>30s}  {:8.2f}"
        .format("Most # of Commands Run",
        max(command_count_data)))

    print("{:>30s}  {:8.2f}\n\n"
        .format("Average # of Commands Run",
        sum(command_count_data)/len(command_count_data)))

def print_commands(data, session):
    for each_entry in data:
        if each_entry['session'] == session:
            if "cowrie.command.input" in each_entry['eventid']:
                print("# " + each_entry['input'])

if len(file_list) == 0: quit()
for each_file in file_list:
    if ".json" in each_file:
        file_path = log_location + "/" + each_file
        with open(file_path, 'r') as file:
            print("Processing file " + file_path)
            for each_line in file:
                json_file = json.loads(each_line)
                data.append(json_file)
            file.close()

vt_session = requests.session()
dshield_session = requests.session()
uh_session = requests.session()

if (session_id):
    sessions = [session_id]
    print_session_info(data, sessions)

elif (tty_file):
    session_id = get_session_id(data, "tty", tty_file)
    print_session_info(data, session_id)

elif (download_file):
    session_id = get_session_id(data, "download", download_file)
    print_session_info(data, session_id)

vt_session.close()
dshield_session.close()
uh_session.close()

