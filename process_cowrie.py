from distutils import command
from gc import collect
import json
from operator import contains
import os
import requests
from os.path import exists
import time
import re
import datetime
import argparse
from pathlib import Path
import collections

date = datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")

parser = argparse.ArgumentParser(description='DShield Honeypot Cowrie Data Identifiers')
parser.add_argument('--logpath', dest='logpath', type=str, help='Path of cowrie json log files', default='/srv/cowrie/var/log/cowrie')
parser.add_argument('--ttyfile', dest='ttyfile', type=str, help='Name of TTY associated TTY log file')
parser.add_argument('--downloadfile', dest='downloadfile', type=str, help='Name of downloaded file (matches file SHA-256 hash)')
parser.add_argument('--session', dest='session', type=str, help='Cowrie session number')
parser.add_argument('--vtapi', dest='vtapi', type=str, help='VirusTotal API key (required for VT data lookup)')
parser.add_argument('--email', dest='email', type=str, help='Your email address (required for DShield IP lookup)')
parser.add_argument('--summarizedays', dest='summarizedays', type=str, help='Will summarize all attacks in the give number of days')

args = parser.parse_args()

log_location = args.logpath
tty_file = args.ttyfile
download_file = args.downloadfile
session_id = args.session
vtapi = args.vtapi
email = args.email
summarizedays = args.summarizedays

os.mkdir(date)
os.chdir(date)

data = []
attack_count = 0
number_of_commands = []
vt_classifications = []
vt_recent_submissions = set()
abnormal_attacks = set()
uncommon_command_counts = set()

file_list = sorted(Path(log_location).iterdir(), key=os.path.getmtime)

list_of_files = []
for each_file in file_list:
    if ".json" in each_file.name:
        list_of_files.append(each_file.name)

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
    elif (type == "all"):
        for each_entry in data:
            if ("shasum" in each_entry):
                if ("src_ip" in each_entry):
                    sessions.add(each_entry['session'])
            if ("ttylog" in each_entry):
                if ("src_ip" in each_entry):
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


def print_session_info(data, sessions, attack_type):
    for session in sessions:
        global attack_count
        attack_count += 1
        protocol = get_protocol_login(session, data)
        username, password, timestamp, src_ip = get_login_data(session, data)
        command_count = get_command_total(session, data)
        number_of_commands.append(command_count)

        downloaddata = get_file_download(session, data)
        uploaddata = get_file_upload(session, data)

        attackstring = "{:>30s}  {:50s}".format("Session",session) + "\n"
        attackstring += "{:>30s}  {:50s}".format("Protocol",protocol) + "\n"
        attackstring += "{:>30s}  {:50s}".format("Username",username) + "\n"
        attackstring += "{:>30s}  {:50s}".format("Password",password) + "\n"
        attackstring += "{:>30s}  {:50s}".format("Timestamp",timestamp) + "\n"
        attackstring += "{:>30s}  {:50s}".format("Source IP Address",src_ip) + "\n"
        attackstring += "{:>30s}  {:50s}".format("URLhaus IP Tags",read_uh_data(src_ip)) + "\n"

        if(email):
            json_data = dshield_query(src_ip)
            attackstring += "{:>30s}  {:50s}".format("ASNAME",(json_data['ip']['asname'])) + "\n"
            attackstring += "{:>30s}  {:50s}".format("ASCOUNTRY",(json_data['ip']['ascountry'])) + "\n"
            attackstring += "{:>30s}  {:<6d}".format("Total Commands Run",command_count) + "\n"

        if len(downloaddata) > 0:
            attackstring += "\n------------------- DOWNLOAD DATA -------------------\n"
        for each_download in downloaddata:
            if(each_download[1]):
                attackstring += "\n"
                attackstring += "{:>30s}  {:50s}".format("Download URL",each_download[0]) + "\n"
                attackstring += "{:>30s}  {:50s}".format("Download SHA-256 Hash",each_download[1]) + "\n"
                attackstring += "{:>30s}  {:50s}".format("Destination File",each_download[3]) + "\n"

                if (not(exists(each_download[1])) and vtapi):
                    vt_query(each_download[1])
                    time.sleep(15)

                if (exists(each_download[1]) and vtapi):
                    vt_description, vt_threat_classification, vt_first_submission, vt_malicious = read_vt_data(each_download[1])
                    attackstring += "{:>30s}  {:50s}".format("VT Description",(vt_description)) + "\n"
                    attackstring += "{:>30s}  {:50s}".format("VT Threat Classification",(vt_threat_classification)) + "\n"
                    if vt_threat_classification == "":
                        vt_classifications.append("<blank>") 
                        abnormal_attacks.add(session)
                    else:
                        vt_classifications.append(vt_threat_classification)
                    attackstring += "{:>30s}  {}".format("VT First Submssion",(datetime.datetime.fromtimestamp(int(vt_first_submission)))) + "\n"
                    if (datetime.datetime.now() - datetime.datetime.fromtimestamp(int(vt_first_submission))).days <= 5:
                        abnormal_attacks.add(session)
                        vt_recent_submissions.add(session)
                    attackstring += "{:>30s}  {:<6d}".format("VT Malicious Hits",(vt_malicious)) + "\n"

                if (each_download[2] != "" and email):
                    if (re.search('[a-zA-Z]', each_download[2])):
                        attackstring += "{:>30s}  {:50s}".format("Download Source Address",each_download[2]) + "\n"
                        attackstring += "{:>30s}  {:50s}".format("URLhaus Source Tags",read_uh_data(each_download[2])) + "\n"

                    else:
                        json_data = dshield_query(each_download[2])
                        attackstring += "{:>30s}  {:50s}".format("Download Source Address",each_download[2]) + "\n"
                        attackstring += "{:>30s}  {:50s}".format("URLhaus IP Tags",read_uh_data(each_download[2])) + "\n"
                        attackstring += "{:>30s}  {:50s}".format("ASNAME",(json_data['ip']['asname'])) + "\n"
                        attackstring += "{:>30s}  {:50s}".format("ASCOUNTRY",(json_data['ip']['ascountry'])) + "\n"

        if len(uploaddata) > 0:
            attackstring += "\n------------------- UPLOAD DATA -------------------\n"
        for each_upload in uploaddata:
            if(each_upload[1]):
                attackstring += "\n"
                attackstring += "{:>30s}  {:50s}".format("Upload URL",each_upload[0]) + "\n"
                attackstring += "{:>30s}  {:50s}".format("Upload SHA-256 Hash",each_upload[1]) + "\n"
                attackstring += "{:>30s}  {:50s}".format("Destination File",each_upload[3]) + "\n"

                if (not(exists(each_upload[1])) and vtapi):
                    vt_query(each_upload[1])
                    time.sleep(15)

                if (exists(each_upload[1]) and vtapi):
                    vt_description, vt_threat_classification, vt_first_submission, vt_malicious = read_vt_data(each_upload[1])
                    attackstring += "{:>30s}  {:50s}".format("VT Description",(vt_description)) + "\n"
                    attackstring += "{:>30s}  {:50s}".format("VT Threat Classification",(vt_threat_classification)) + "\n"
                    attackstring += "{:>30s}  {}".format("VT First Submssion",(datetime.datetime.fromtimestamp(int(vt_first_submission)))) + "\n"
                    attackstring += "{:>30s}  {:<6d}".format("VT Malicious Hits",(vt_malicious)) + "\n"

                if (each_upload[2] != "" and email):
                    if (re.search('[a-zA-Z]', each_upload[2])):
                        attackstring += "{:>30s}  {:50s}".format("Upload Source Address",each_upload[2]) + "\n"
                        attackstring += "{:>30s}  {:50s}".format("URLhaus IP Tags",read_uh_data(each_upload[2])) + "\n"

                    else:
                        json_data = dshield_query(each_upload[2])
                        attackstring += "{:>30s}  {:50s}".format("Upload Source Address",each_upload[2]) + "\n"
                        attackstring += "{:>30s}  {:50s}".format("URLhaus IP Tags",read_uh_data(each_upload[2])) + "\n"
                        attackstring += "{:>30s}  {:50s}".format("ASNAME",(json_data['ip']['asname'])) + "\n"
                        attackstring += "{:>30s}  {:50s}".format("ASCOUNTRY",(json_data['ip']['ascountry'])) + "\n"



        attackstring += "\n////////////////// COMMANDS ATTEMPTED //////////////////\n\n"
        attackstring += get_commands(data, session) + "\n"
        attackstring += "\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\n"
        print(attackstring)

        if (attack_type == "abnormal"):
            if (summarizedays):
                report_file = open(date + "_abnormal_" + summarizedays + "-day_report.txt","a")
            else:
                report_file = open(date + "abnormal_report.txt","a")
            report_file.write(attackstring)
            report_file.close()
        else:
            if (summarizedays):
                report_file = open(date + "_" + summarizedays + "_day_report.txt","a")
            else:
                report_file = open(date + "_report.txt","a")
            report_file.write(attackstring)
            report_file.close()

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

def get_commands(data, session):
    commands = ""
    for each_entry in data:
        if each_entry['session'] == session:
            if "cowrie.command.input" in each_entry['eventid']:
                commands += "# " + each_entry['input'] + "\n"
    return commands

if len(file_list) == 0: quit()

if (summarizedays):
    days = int(summarizedays)
    print("Days to summarize: " + str(days))
    file_list = []
    i = 0
    for each_file in list_of_files:
        if i < int(days):
            file_list.append(list_of_files.pop())
            i += 1
    list_of_files = file_list

for each_file in list_of_files:
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

if (summarizedays):
    session_id = get_session_id(data, "all", "unnecessary")
    print_session_info(data, session_id, "standard")

elif (session_id):
    sessions = [session_id]
    print_session_info(data, sessions, "standard")

elif (tty_file):
    session_id = get_session_id(data, "tty", tty_file)
    print_session_info(data, session_id, "standard")

elif (download_file):
    session_id = get_session_id(data, "download", download_file)
    print_session_info(data, session_id, "standard")

counts = collections.Counter(number_of_commands)
number_of_commands = sorted(number_of_commands, key=lambda x: -counts[x])
commands = set()
for num_count in number_of_commands:
    commands.add(num_count)

vt_counts = collections.Counter(vt_classifications)
vt_classifications = sorted(vt_classifications, key=lambda x: -vt_counts[x])
vt_class = set()
for classification in vt_classifications:
    vt_class.add(classification)


if (summarizedays):
    for each_session in session_id:
        command_count = get_command_total(each_session, data)
        #if command_count != number_of_commands[0]:
        if number_of_commands.count(command_count) < 5:
            abnormal_attacks.add(each_session)
            uncommon_command_counts.add(each_session)


elif (session_id):
    sessions = [session_id]
    for each_session in sessions:
        command_count = get_command_total(each_session, data)
        #if command_count != number_of_commands[0]:
        if number_of_commands.count(command_count) < 5:
            abnormal_attacks.add(each_session)
            uncommon_command_counts.add(each_session)

elif (tty_file):
    for each_session in session_id:
        command_count = get_command_total(each_session, data)
        #if command_count != number_of_commands[0]:
        if number_of_commands.count(command_count) < 5:
            abnormal_attacks.add(each_session)
            uncommon_command_counts.add(each_session)


elif (download_file):
    for each_session in session_id:
        command_count = get_command_total(each_session, data)
        #if command_count != number_of_commands[0]:
        if number_of_commands.count(command_count) < 5:
            abnormal_attacks.add(each_session)
            uncommon_command_counts.add(each_session)

print_session_info(data, abnormal_attacks, "abnormal")

vt_session.close()
dshield_session.close()
uh_session.close()

summarystring = "{:>40s}  {:10s}".format("Total Number of Attacks:", str(attack_count)) + "\n"
summarystring += "{:>40s}  {:10s}".format("Most Common Number of Commands:", str(number_of_commands[0])) + "\n"
summarystring += "\n"
summarystring += "{:>40s}  {:10s}".format("Number of Commands", "Times Seen") + "\n"
summarystring += "{:>40s}  {:10s}".format("------------------", "----------") + "\n"
for command in commands:
    summarystring += "{:>40s}  {:10s}".format(str(command), str(number_of_commands.count(command))) + "\n"
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

print(summarystring)
if (summarizedays):
    report_file = open(date + "_" + summarizedays + "_day_report.txt","a")
else:
    report_file = open(date + "_report.txt","a")
report_file.write(summarystring)
report_file.close()
