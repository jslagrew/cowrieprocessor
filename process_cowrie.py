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
import dropbox
import sqlite3
import logging
import sys
import socket

logging_fhandler = logging.FileHandler("cowrieprocessor.err")
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

#string prepended to filename for report summaries
#may want a '_' at the start of this string for readability
hostname = socket.gethostname()
filename_prepend = f"_{hostname}"

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

con = sqlite3.connect('../cowrieprocessor.sqlite')

def initialize_database():
    logging.info("Database initializing...")
    cur = con.cursor()
    cur.execute('''
            CREATE TABLE IF NOT EXISTS sessions(session text,
                session_duration int,
                protocol text,
                username text,
                password text,
                timestamp int,
                source_ip text,
                urlhaus_tag text,
                asname text,
                ascountry text,
                spur_asn text,
                spur_asn_organization text,
                spur_organization text,
                spur_infrastructure text,
                spur_client_behaviors text,
                spur_client_proxies text,
                spur_client_types text,
                spur_client_count text,
                spur_client_concentration text,
                spur_client_countries text,
                spur_geospread text,
                spur_risks text,
                spur_services text,
                spur_location text,
                spur_tunnel_anonymous text,
                spur_tunnel_entries text,
                spur_tunnel_operator text,
                spur_tunnel_type text,
                total_commands int,
                added int)''')
    cur.execute('''
            CREATE TABLE IF NOT EXISTS commands(session text,
                command text,
                timestamp int,
                added int)''')
    cur.execute('''
            CREATE TABLE IF NOT EXISTS files(session text,
                download_url text,
                hash text,
                file_path text,
                vt_description text,
                vt_threat_classification text,
                vt_first_submission int,
                vt_hits int,
                src_ip text,
                urlhaus_tag text,
                asname text,
                ascountry text,
                spur_asn text,
                spur_asn_organization text,
                spur_organization text,
                spur_infrastructure text,
                spur_client_behaviors text,
                spur_client_proxies text,
                spur_client_types text,
                spur_client_count text,
                spur_client_concentration text,
                spur_client_countries text,
                spur_geospread text,
                spur_risks text,
                spur_services text,
                spur_location text,
                spur_tunnel_anonymous text,
                spur_tunnel_entries text,
                spur_tunnel_operator text,
                spur_tunnel_type text,
                transfer_method text,
                added int)''')
    con.commit()

    try:
        #add new columns for spur data in preexisting databases
        cur.execute('''ALTER TABLE sessions ADD spur_asn text''')
        cur.execute('''ALTER TABLE sessions ADD spur_asn_organization text''')
        cur.execute('''ALTER TABLE sessions ADD spur_organization text''')
        cur.execute('''ALTER TABLE sessions ADD spur_infrastructure text''')
        cur.execute('''ALTER TABLE sessions ADD spur_client_behaviors text''')
        cur.execute('''ALTER TABLE sessions ADD spur_client_proxies text''')
        cur.execute('''ALTER TABLE sessions ADD spur_client_types text''')
        cur.execute('''ALTER TABLE sessions ADD spur_client_count text''')
        cur.execute('''ALTER TABLE sessions ADD spur_client_concentration text''')
        cur.execute('''ALTER TABLE sessions ADD spur_client_countries text''')
        cur.execute('''ALTER TABLE sessions ADD spur_geospread text''')
        cur.execute('''ALTER TABLE sessions ADD spur_risks text''')
        cur.execute('''ALTER TABLE sessions ADD spur_services text''')
        cur.execute('''ALTER TABLE sessions ADD spur_location text''')
        cur.execute('''ALTER TABLE sessions ADD spur_tunnel_anonymous text''')
        cur.execute('''ALTER TABLE sessions ADD spur_tunnel_entries text''')
        cur.execute('''ALTER TABLE sessions ADD spur_tunnel_operator text''')
        cur.execute('''ALTER TABLE sessions ADD spur_tunnel_type text''')        
        cur.execute('''ALTER TABLE files ADD spur_asn text''')
        cur.execute('''ALTER TABLE files ADD spur_asn_organization text''')
        cur.execute('''ALTER TABLE files ADD spur_organization text''')
        cur.execute('''ALTER TABLE files ADD spur_infrastructure text''')
        cur.execute('''ALTER TABLE files ADD spur_client_behaviors text''')
        cur.execute('''ALTER TABLE files ADD spur_client_proxies text''')
        cur.execute('''ALTER TABLE files ADD spur_client_types text''')
        cur.execute('''ALTER TABLE files ADD spur_client_count text''')
        cur.execute('''ALTER TABLE files ADD spur_client_concentration text''')
        cur.execute('''ALTER TABLE files ADD spur_client_countries text''')
        cur.execute('''ALTER TABLE files ADD spur_geospread text''')
        cur.execute('''ALTER TABLE files ADD spur_risks text''')
        cur.execute('''ALTER TABLE files ADD spur_services text''')
        cur.execute('''ALTER TABLE files ADD spur_location text''')
        cur.execute('''ALTER TABLE files ADD spur_tunnel_anonymous text''')
        cur.execute('''ALTER TABLE files ADD spur_tunnel_entries text''')
        cur.execute('''ALTER TABLE files ADD spur_tunnel_operator text''')
        cur.execute('''ALTER TABLE files ADD spur_tunnel_type text''')
        con.commit()        
    except:
        print("Failure adding table columns, likely because they already exist...")

    try:
        #add new columns for spur data in preexisting databases
        cur.execute('''ALTER TABLE sessions ADD spur_tunnel_anonymous text''')
        cur.execute('''ALTER TABLE sessions ADD spur_tunnel_entries text''')
        cur.execute('''ALTER TABLE sessions ADD spur_tunnel_operator text''')
        cur.execute('''ALTER TABLE sessions ADD spur_tunnel_type text''')      
        cur.execute('''ALTER TABLE sessions ADD spur_client_proxies text''')  
        cur.execute('''ALTER TABLE files ADD spur_tunnel_anonymous text''')
        cur.execute('''ALTER TABLE files ADD spur_tunnel_entries text''')
        cur.execute('''ALTER TABLE files ADD spur_tunnel_operator text''')
        cur.execute('''ALTER TABLE files ADD spur_tunnel_type text''')
        cur.execute('''ALTER TABLE files ADD spur_client_proxies text''')
        con.commit()        
    except:
        logging.error("Failure adding table columns, likely because they already exist...")
    try:
        #add new columns for spur data in preexisting databases
        cur.execute('''ALTER TABLE sessions ADD session_duration int''')
        con.commit()        
    except:
        logging.error("Failure adding table columns, likely because they already exist...")        

def get_connected_sessions(data):
    logging.info("Extracting unique sessions...")
    sessions = set()
    for each_entry in data:
        if each_entry['eventid'] == "cowrie.login.success": 
            sessions.add(each_entry['session'])
    return sessions

def get_session_id(data, type, match):
    logging.info("Extracting unique sessions")
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

def get_session_duration(session, data):
    logging.info("Getting session durations...")
    duration = ""
    for each_entry in data:
        if each_entry['session'] == session:
            if each_entry['eventid'] == "cowrie.session.closed":
                duration = each_entry['duration']

    return duration

def get_protocol_login(session, data):
    logging.info("Getting protocol from session connection...")
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
                        download_ip = re.findall(r"\:\/\/(.*?)\/",each_entry['url'])[0]
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
                        upload_ip = re.findall(r"\:\/\/(.*?)\/",each_entry['url'])[0]
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

def spur_query(ip_address):
    spur_session.headers = {'Token': spurapi}
    #token = {'Token': api_spur}
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
    file = open("spur" + "_" +ip_address.replace(":", "_") + ".json", 'w',encoding="utf-8")
    file.write(response.text)
    file.close()

def read_spur_data(ip_address):
    global summary_text
    if not exists("spur" + "_" + ip_address.replace(":", "_") + ".json"):
        spur_query(ip_address)
    spur_data = open("spur" + "_" + ip_address.replace(":", "_") + ".json", 'r',encoding="utf-8")
    file = ""
    for eachline in spur_data:
        file += eachline
    spur_data.close
    json_data = json.loads(file)

    spur_list = []
    if ("as" in json_data):
        if ("number" in json_data['as']):
            as_number = json_data['as']['number']
        else:
            as_number = ""
        spur_list.append(as_number)

        if ("organization" in json_data['as']):
            as_organization = json_data['as']['organization']       
        else:
            as_organization = ""    
        spur_list.append(as_organization)

    if ("organization" in json_data):
        organization = json_data['organization']
    else:
        organization = ""
    spur_list.append(organization)

    if ("infrastructure" in json_data):
        infrastructure = json_data['infrastructure']
    else:
        infrastructure = ""
    spur_list.append(infrastructure)

    if ("client" in json_data):
        if ("behaviors" in json_data['client']):
            client_behaviors = json_data['client']['behaviors']
        else:
            client_behaviors = ""
        if ("proxies" in json_data['client']):
            client_proxies = json_data['client']['proxies']
        else:
            client_proxies = ""
        if ("types" in json_data['client']):
            client_types = json_data['client']['types']
        else:
            client_types = ""
        if ("count" in json_data['client']):
            client_count = str(json_data['client']['count'])
        else:
            client_count = ""
        if ("concentration" in json_data['client']):
            client_concentration = json_data['client']['concentration']
        else:
            client_concentration = ""
        if ("countries" in json_data['client']):
            client_countries = json_data['client']['countries']
        else:
            client_countries = ""
        if ("spread" in json_data['client']):
            client_spread = json_data['client']['spread']     
        else:
            client_spread = ""  
    else:
        client_behaviors = ""
        client_proxies = ""
        client_types = ""
        client_count = ""
        client_concentration = ""
        client_countries = ""
        client_spread = ""
    spur_list.append(client_behaviors)
    spur_list.append(client_proxies)
    spur_list.append(client_types)
    spur_list.append(client_count)
    spur_list.append(client_concentration)
    spur_list.append(client_countries)
    spur_list.append(client_spread)

    if ("risks" in json_data):
        risks = json_data['risks']
    else:
        risks = ""
    spur_list.append(risks)

    if ("services" in json_data):
        services = json_data['services']
    else:
        services = ""
    spur_list.append(services)

    if ("location" in json_data):
        city = ""
        state = ""
        country = ""
        if ("city" in json_data['location']):
            city = json_data['location']['city'] + ", "
        if ("state" in json_data['location']):
            state = json_data['location']['state'] + ", "
        if ("country" in json_data['location']):
            country = json_data['location']['country']
        location = city + state + country
    else:
        location = ""
    spur_list.append(location)

    if ("tunnels" in json_data):
        tunnels = ""
        for each_tunnel in json_data['tunnels']:
            if ("anonymous" in each_tunnel):
                tunnel_anonymous = each_tunnel['anonymous']
            else:
                tunnel_anonymous = ""
            if ("entries" in each_tunnel):
                tunnel_entries = each_tunnel['entries']
            else:
                tunnel_entries = ""
            if ("operator" in each_tunnel):
                tunnel_operator = each_tunnel['operator']
            else:
                tunnel_operator = ""
            if ("type" in each_tunnel):
                tunnel_type = each_tunnel['type']
            else:
                tunnel_type = ""
    else:
        tunnel_anonymous = ""
        tunnel_entries = ""
        tunnel_operator = ""
        tunnel_type = ""
    spur_list.append(tunnel_anonymous)
    spur_list.append(tunnel_entries)
    spur_list.append(tunnel_operator)
    spur_list.append(tunnel_type)
    
    return spur_list


def print_session_info(data, sessions, attack_type):
    for session in sessions:
        cur = con.cursor()
        global attack_count
        attack_count += 1
        protocol = get_protocol_login(session, data)
        session_duration = get_session_duration(session, data)

        #try block for partially available data
        #this is usually needed due to an attack spanning multiple log files not included for processing
        try:
            username, password, timestamp, src_ip = get_login_data(session, data)
        except:
            continue
        command_count = get_command_total(session, data)
        print("Command Count: " + str(command_count))
        number_of_commands.append(command_count)

        downloaddata = get_file_download(session, data)
        uploaddata = get_file_upload(session, data)

        attackstring = "{:>30s}  {:50s}".format("Session",str(session)) + "\n"
        attackstring += "{:>30s}  {:50s}".format("Session Duration",str(session_duration)[0:5] + " seconds") + "\n"
        attackstring += "{:>30s}  {:50s}".format("Protocol",str(protocol)) + "\n"
        attackstring += "{:>30s}  {:50s}".format("Username",str(username)) + "\n"
        attackstring += "{:>30s}  {:50s}".format("Password",str(password)) + "\n"
        attackstring += "{:>30s}  {:50s}".format("Timestamp",str(timestamp)) + "\n"
        attackstring += "{:>30s}  {:50s}".format("Source IP Address",str(src_ip)) + "\n"
        if urlhausapi is not None:
            attackstring += "{:>30s}  {:50s}".format("URLhaus IP Tags",str(read_uh_data(src_ip, urlhausapi))) + "\n"

        if(email):
            json_data = dshield_query(src_ip)
            attackstring += "{:>30s}  {:50s}".format("ASNAME",(json_data['ip']['asname'])) + "\n"
            attackstring += "{:>30s}  {:50s}".format("ASCOUNTRY",(json_data['ip']['ascountry'])) + "\n"
            attackstring += "{:>30s}  {:<6d}".format("Total Commands Run",command_count) + "\n"

        if(spurapi):
            spur_session_data = read_spur_data(src_ip)
            if spur_session_data[0] != "":
                attackstring += "{:>30s}  {:<50s}".format("SPUR ASN", str(spur_session_data[0])) + "\n"
            if spur_session_data[1] != "":
                attackstring += "{:>30s}  {:<50s}".format("SPUR ASN Organization", str(spur_session_data[1])) + "\n"
            if spur_session_data[2] != "":
                attackstring += "{:>30s}  {:<50s}".format("SPUR Organization", str(spur_session_data[2])) + "\n"     
            if spur_session_data[3] != "":                
                attackstring += "{:>30s}  {:<50s}".format("SPUR Infrastructure", str(spur_session_data[3]))  + "\n"      
            if spur_session_data[4] != "":                
                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Behaviors", str(spur_session_data[4])) + "\n"  
            if spur_session_data[5] != "":                
                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Proxies", str(spur_session_data[5])) + "\n"  
            if spur_session_data[6] != "":               
                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Types", str(spur_session_data[6])) + "\n"  
            if spur_session_data[7] != "":                
                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Count", str(spur_session_data[7])) + "\n"  
            if spur_session_data[8] != "":               
                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Concentration", str(spur_session_data[8])) + "\n"  
            if spur_session_data[9] != "":                
                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Countries", str(spur_session_data[9])) + "\n"    
            if spur_session_data[10] != "":                
                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Geo-spread", str(spur_session_data[10])) + "\n"    
            if spur_session_data[11] != "":                
                attackstring += "{:>30s}  {:<50s}".format("SPUR Risks", str(spur_session_data[11])) + "\n"  
            if spur_session_data[12] != "":                
                attackstring += "{:>30s}  {:<50s}".format("SPUR Services", str(spur_session_data[12])) + "\n"  
            if spur_session_data[13] != "":                
                attackstring += "{:>30s}  {:<50s}".format("SPUR Location", str(spur_session_data[13])) + "\n"  
            if spur_session_data[14] != "":                
                attackstring += "{:>30s}  {:<50s}".format("SPUR Anonymous Tunnel", str(spur_session_data[14])) + "\n"   
            if spur_session_data[15] != "":                
                attackstring += "{:>30s}  {:<50s}".format("SPUR Tunnel Entries", str(spur_session_data[15])) + "\n"  
            if spur_session_data[16] != "":                
                attackstring += "{:>30s}  {:<50s}".format("SPUR Tunnel Operator", str(spur_session_data[16])) + "\n"  
            if spur_session_data[17] != "":                
                attackstring += "{:>30s}  {:<50s}".format("SPUR Tunnel Type", str(spur_session_data[17])) + "\n"  


        if len(downloaddata) > 0:
            attackstring += "\n------------------- DOWNLOAD DATA -------------------\n"
        for each_download in downloaddata:
            if(each_download[1]):
                attackstring += "\n"
                attackstring += "{:>30s}  {:50s}".format("Download URL",each_download[0]) + "\n"
                attackstring += "{:>30s}  {:50s}".format("Download SHA-256 Hash",each_download[1]) + "\n"
                attackstring += "{:>30s}  {:50s}".format("Destination File",each_download[3]) + "\n"

                sql = '''SELECT * FROM files WHERE session=? and hash=? and file_path=?'''
                cur.execute(sql, (session, each_download[1], each_download[3]))
                rows = cur.fetchall()
                download_data_needed = len(rows)

                if(download_data_needed > 0):
                    print("Download data for session " + session + " was already stored within database")
                else:
                    sql = '''INSERT INTO files(session, download_url, hash, file_path) VALUES (?,?,?,?)'''
                    cur.execute(sql, (session, each_download[0], each_download[1], each_download[3]))
                    con.commit()


                if (not(exists(each_download[1])) and vtapi):
                    vt_query(each_download[1])
                    time.sleep(15)

                if (exists(each_download[1]) and vtapi):
                    vt_description, vt_threat_classification, vt_first_submission, vt_malicious = read_vt_data(each_download[1])
                    attackstring += "{:>30s}  {:50s}".format("VT Description",(vt_description)) + "\n"
                    attackstring += "{:>30s}  {:50s}".format("VT Threat Classification",(vt_threat_classification)) + "\n"
                    if(download_data_needed == 0):
                        sql = '''UPDATE files SET vt_description=?, vt_threat_classification=?, vt_first_submission=?, 
                            vt_hits=?, transfer_method=?, added=? WHERE session=? and hash=?'''
                        cur.execute(sql, (vt_description, vt_threat_classification, vt_first_submission, vt_malicious,
                            "DOWNLOAD", time.time(), session, each_download[1]))
                        con.commit()
                    if vt_threat_classification == "":
                        vt_classifications.append("<blank>") 
                        #commented out due to too many inclusions from hosts.deny data
                        #abnormal_attacks.add(session)
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
                        if urlhausapi is not None:
                            attackstring += "{:>30s}  {:50s}".format("URLhaus Source Tags",read_uh_data(each_download[2], urlhausapi)) + "\n"
                            sql = '''UPDATE files SET src_ip=?, urlhaus_tag=? WHERE session=? and hash=?'''
                            cur.execute(sql, (each_download[2], read_uh_data(each_download[2], urlhausapi), session, each_download[1]))
                            con.commit()
                    else:
                        json_data = dshield_query(each_download[2])
                        attackstring += "{:>30s}  {:50s}".format("Download Source Address",each_download[2]) + "\n"
                        if urlhausapi is not None:
                            attackstring += "{:>30s}  {:50s}".format("URLhaus IP Tags",read_uh_data(each_download[2], urlhausapi)) + "\n"
                        attackstring += "{:>30s}  {:50s}".format("ASNAME",(json_data['ip']['asname'])) + "\n"
                        attackstring += "{:>30s}  {:50s}".format("ASCOUNTRY",(json_data['ip']['ascountry'])) + "\n"

                        if(spurapi):
                            spur_data = read_spur_data(src_ip)
                            if spur_data[0] != "":
                                attackstring += "{:>30s}  {:<50s}".format("SPUR ASN", str(spur_data[0])) + "\n"
                            if spur_data[1] != "":
                                attackstring += "{:>30s}  {:<50s}".format("SPUR ASN Organization", str(spur_data[1])) + "\n"
                            if spur_data[2] != "":
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Organization", str(spur_data[2])) + "\n"     
                            if spur_data[3] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Infrastructure", str(spur_data[3]))  + "\n"      
                            if spur_data[4] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Behaviors", str(spur_data[4])) + "\n"  
                            if spur_data[5] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Proxies", str(spur_data[5])) + "\n"  
                            if spur_data[6] != "":               
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Types", str(spur_data[6])) + "\n"  
                            if spur_data[7] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Count", str(spur_data[7])) + "\n"  
                            if spur_data[8] != "":               
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Concentration", str(spur_data[8])) + "\n"  
                            if spur_data[9] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Countries", str(spur_data[9])) + "\n"    
                            if spur_data[10] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Geo-spread", str(spur_data[10])) + "\n"    
                            if spur_data[11] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Risks", str(spur_data[11])) + "\n"  
                            if spur_data[12] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Services", str(spur_data[12])) + "\n"  
                            if spur_data[13] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Location", str(spur_data[13])) + "\n"  
                            if spur_data[14] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Anonymous Tunnel", str(spur_data[14])) + "\n"   
                            if spur_data[15] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Tunnel Entries", str(spur_data[15])) + "\n"  
                            if spur_data[16] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Tunnel Operator", str(spur_data[16])) + "\n"  
                            if spur_data[17] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Tunnel Type", str(spur_data[17])) + "\n"  
                        
                            sql = '''UPDATE files SET src_ip=?, urlhaus_tag=?, asname=?, ascountry=?,
                                spur_asn=?,
                                spur_asn_organization=?,
                                spur_organization=?,
                                spur_infrastructure=?,
                                spur_client_behaviors=?,
                                spur_client_proxies=?,
                                spur_client_types=?,
                                spur_client_count=?,
                                spur_client_concentration=?,
                                spur_client_countries=?,
                                spur_geospread=?,
                                spur_risks=?,
                                spur_services=?,
                                spur_location=?,
                                spur_tunnel_anonymous=?,
                                spur_tunnel_entries=?,
                                spur_tunnel_operator=?,
                                spur_tunnel_type=?                             
                                WHERE session=? and hash=?'''
                            if urlhausapi is not None:
                                cur.execute(sql, (each_download[2], read_uh_data(each_download[2], urlhausapi), json_data['ip']['asname'], json_data['ip']['ascountry'],
                                                str(spur_data[0]),
                                                str(spur_data[1]),
                                                str(spur_data[2]),
                                                str(spur_data[3]),
                                                str(spur_data[4]),
                                                str(spur_data[5]),
                                                str(spur_data[6]),
                                                str(spur_data[7]),
                                                str(spur_data[8]),
                                                str(spur_data[9]),
                                                str(spur_data[10]),
                                                str(spur_data[11]),
                                                str(spur_data[12]),
                                                str(spur_data[13]),
                                                str(spur_data[14]),
                                                str(spur_data[15]),
                                                str(spur_data[16]),
                                                str(spur_data[17]),
                                                session, each_download[1]))
                            else:
                                cur.execute(sql, (each_download[2], "", json_data['ip']['asname'], json_data['ip']['ascountry'],
                                                str(spur_data[0]),
                                                str(spur_data[1]),
                                                str(spur_data[2]),
                                                str(spur_data[3]),
                                                str(spur_data[4]),
                                                str(spur_data[5]),
                                                str(spur_data[6]),
                                                str(spur_data[7]),
                                                str(spur_data[8]),
                                                str(spur_data[9]),
                                                str(spur_data[10]),
                                                str(spur_data[11]),
                                                str(spur_data[12]),
                                                str(spur_data[13]),
                                                str(spur_data[14]),
                                                str(spur_data[15]),
                                                str(spur_data[16]),
                                                str(spur_data[17]),
                                                session, each_download[1]))                                
                            con.commit()




        if len(uploaddata) > 0:
            attackstring += "\n------------------- UPLOAD DATA -------------------\n"
        for each_upload in uploaddata:
            if(each_upload[1]):
                attackstring += "\n"
                attackstring += "{:>30s}  {:50s}".format("Upload URL",each_upload[0]) + "\n"
                attackstring += "{:>30s}  {:50s}".format("Upload SHA-256 Hash",each_upload[1]) + "\n"
                attackstring += "{:>30s}  {:50s}".format("Destination File",each_upload[3]) + "\n"

                sql = '''SELECT * FROM files WHERE session=? and hash=? and file_path=?'''
                cur.execute(sql, (session, each_upload[1], each_upload[3]))
                rows = cur.fetchall()
                upload_data_needed = len(rows)

                if(upload_data_needed > 0):
                    print("Upload data for session " + session + " was already stored within database")
                else:
                    sql = '''INSERT INTO files(session, download_url, hash, file_path) VALUES (?,?,?,?)'''
                    cur.execute(sql, (session, each_upload[0], each_upload[1], each_upload[3]))
                    con.commit()

                if (not(exists(each_upload[1])) and vtapi):
                    vt_query(each_upload[1])
                    time.sleep(15)

                if (exists(each_upload[1]) and vtapi):
                    vt_description, vt_threat_classification, vt_first_submission, vt_malicious = read_vt_data(each_upload[1])
                    attackstring += "{:>30s}  {:50s}".format("VT Description",(vt_description)) + "\n"
                    attackstring += "{:>30s}  {:50s}".format("VT Threat Classification",(vt_threat_classification)) + "\n"
                    attackstring += "{:>30s}  {}".format("VT First Submssion",(datetime.datetime.fromtimestamp(int(vt_first_submission)))) + "\n"
                    attackstring += "{:>30s}  {:<6d}".format("VT Malicious Hits",(vt_malicious)) + "\n"

                    if(upload_data_needed == 0):
                        sql = '''UPDATE files SET vt_description=?, vt_threat_classification=?, vt_first_submission=?,
                            vt_hits=?, transfer_method=?, added=? WHERE session=? and hash=?'''
                        cur.execute(sql, (vt_description, vt_threat_classification, vt_first_submission, vt_malicious,
                            "UPLOAD", time.time(), session, each_upload[1]))
                        con.commit()

                if (each_upload[2] != "" and email):
                    if (re.search('[a-zA-Z]', each_upload[2])):
                        attackstring += "{:>30s}  {:50s}".format("Upload Source Address",each_upload[2]) + "\n"
                        if urlhausapi is not None:
                            attackstring += "{:>30s}  {:50s}".format("URLhaus IP Tags",read_uh_data(each_upload[2], urlhausapi)) + "\n"
                            sql = '''UPDATE files SET src_ip=?, urlhaus_tag=? WHERE session=? and hash=?'''
                            cur.execute(sql, (each_upload[2], read_uh_data(each_upload[2], urlhausapi), session, each_upload[1]))
                            con.commit()

                    else:
                        json_data = dshield_query(each_upload[2])
                        attackstring += "{:>30s}  {:50s}".format("Upload Source Address",each_upload[2]) + "\n"
                        if urlhausapi is not None:
                            attackstring += "{:>30s}  {:50s}".format("URLhaus IP Tags",read_uh_data(each_upload[2], urlhausapi)) + "\n"
                        attackstring += "{:>30s}  {:50s}".format("ASNAME",(json_data['ip']['asname'])) + "\n"
                        attackstring += "{:>30s}  {:50s}".format("ASCOUNTRY",(json_data['ip']['ascountry'])) + "\n"


                        if(spurapi):
                            spur_data = read_spur_data(src_ip)
                            if spur_data[0] != "":
                                attackstring += "{:>30s}  {:<50s}".format("SPUR ASN", str(spur_data[0])) + "\n"
                            if spur_data[1] != "":
                                attackstring += "{:>30s}  {:<50s}".format("SPUR ASN Organization", str(spur_data[1])) + "\n"
                            if spur_data[2] != "":
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Organization", str(spur_data[2])) + "\n"     
                            if spur_data[3] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Infrastructure", str(spur_data[3]))  + "\n"      
                            if spur_data[4] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Behaviors", str(spur_data[4])) + "\n"  
                            if spur_data[5] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Proxies", str(spur_data[5])) + "\n"  
                            if spur_data[6] != "":               
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Types", str(spur_data[6])) + "\n"  
                            if spur_data[7] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Count", str(spur_data[7])) + "\n"  
                            if spur_data[8] != "":               
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Concentration", str(spur_data[8])) + "\n"  
                            if spur_data[9] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Countries", str(spur_data[9])) + "\n"    
                            if spur_data[10] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Client Geo-spread", str(spur_data[10])) + "\n"    
                            if spur_data[11] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Risks", str(spur_data[11])) + "\n"  
                            if spur_data[12] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Services", str(spur_data[12])) + "\n"  
                            if spur_data[13] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Location", str(spur_data[13])) + "\n"  
                            if spur_data[14] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Anonymous Tunnel", str(spur_data[14])) + "\n"   
                            if spur_data[15] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Tunnel Entries", str(spur_data[15])) + "\n"  
                            if spur_data[16] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Tunnel Operator", str(spur_data[16])) + "\n"  
                            if spur_data[17] != "":                
                                attackstring += "{:>30s}  {:<50s}".format("SPUR Tunnel Type", str(spur_data[17])) + "\n"                           

                            sql = '''UPDATE files SET src_ip=?, urlhaus_tag=?, asname=?, ascountry=?,
                                spur_asn=?,
                                spur_asn_organization=?,
                                spur_organization=?,
                                spur_infrastructure=?,
                                spur_client_behaviors=?,
                                spur_client_proxies=?,
                                spur_client_types=?,
                                spur_client_count=?,
                                spur_client_concentration=?,
                                spur_client_countries=?,
                                spur_geospread=?,
                                spur_risks=?,
                                spur_services=?,
                                spur_location=?,
                                spur_tunnel_anonymous=?,
                                spur_tunnel_entries=?,
                                spur_tunnel_operator=?,
                                spur_tunnel_type=?                             
                                WHERE session=? and hash=?'''
                            if urlhausapi is not None:
                                cur.execute(sql, (each_upload[2], read_uh_data(each_upload[2], urlhausapi), json_data['ip']['asname'], json_data['ip']['ascountry'],
                                                str(spur_data[0]),
                                                str(spur_data[1]),
                                                str(spur_data[2]),
                                                str(spur_data[3]),
                                                str(spur_data[4]),
                                                str(spur_data[5]),
                                                str(spur_data[6]),
                                                str(spur_data[7]),
                                                str(spur_data[8]),
                                                str(spur_data[9]),
                                                str(spur_data[10]),
                                                str(spur_data[11]),
                                                str(spur_data[12]),
                                                str(spur_data[13]),
                                                str(spur_data[14]),
                                                str(spur_data[15]),
                                                str(spur_data[16]),
                                                str(spur_data[17]),
                                                session, each_upload[1]))
                            else:
                                cur.execute(sql, (each_upload[2], "", json_data['ip']['asname'], json_data['ip']['ascountry'],
                                                str(spur_data[0]),
                                                str(spur_data[1]),
                                                str(spur_data[2]),
                                                str(spur_data[3]),
                                                str(spur_data[4]),
                                                str(spur_data[5]),
                                                str(spur_data[6]),
                                                str(spur_data[7]),
                                                str(spur_data[8]),
                                                str(spur_data[9]),
                                                str(spur_data[10]),
                                                str(spur_data[11]),
                                                str(spur_data[12]),
                                                str(spur_data[13]),
                                                str(spur_data[14]),
                                                str(spur_data[15]),
                                                str(spur_data[16]),
                                                str(spur_data[17]),
                                                session, each_upload[1]))                                
                            con.commit()



        attackstring += "\n////////////////// COMMANDS ATTEMPTED //////////////////\n\n"
        attackstring += get_commands(data, session) + "\n"
        attackstring += "\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\n"
        print(attackstring)

        utc_time = datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
        epoch_time = (utc_time - datetime.datetime(1970, 1, 1)).total_seconds()
        sql = '''SELECT * FROM sessions WHERE session=? and timestamp=?'''
        cur.execute(sql, (session, epoch_time))

        rows = cur.fetchall()
        if (len(rows) > 0):
            print("Data for session " + session + " was already stored within database")
        else:
            sql = '''INSERT INTO sessions( session, session_duration, protocol, username, password, timestamp, source_ip,
                urlhaus_tag, asname, ascountry, total_commands, added) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)'''
            
            if 'json_data' in locals():
                if urlhausapi is not None:
                    cur.execute(sql, (session, session_duration, protocol, username, password, epoch_time, src_ip, read_uh_data(src_ip, urlhausapi),
                        json_data['ip']['asname'], json_data['ip']['ascountry'], command_count, time.time()))
                else:
                    cur.execute(sql, (session, session_duration, protocol, username, password, epoch_time, src_ip, "",
                        json_data['ip']['asname'], json_data['ip']['ascountry'], command_count, time.time()))                    
                con.commit()
            else:
                if urlhausapi is not None:
                    cur.execute(sql, (session, session_duration, protocol, username, password, epoch_time, src_ip, "",
                        "", "", command_count, time.time()))
                else:
                    cur.execute(sql, (session, session_duration, protocol, username, password, epoch_time, src_ip, read_uh_data(src_ip, urlhausapi),
                        "", "", command_count, time.time()))                    
                con.commit()


            if(spurapi):
                sql = '''UPDATE sessions SET 
                    spur_asn=?,
                    spur_asn_organization=?,
                    spur_organization=?,
                    spur_infrastructure=?,
                    spur_client_behaviors=?,
                    spur_client_proxies=?,
                    spur_client_types=?,
                    spur_client_count=?,
                    spur_client_concentration=?,
                    spur_client_countries=?,
                    spur_geospread=?,
                    spur_risks=?,
                    spur_services=?,
                    spur_location=?,
                    spur_tunnel_anonymous=?,
                    spur_tunnel_entries=?,
                    spur_tunnel_operator=?,
                    spur_tunnel_type=?                             
                    WHERE session=? and timestamp=?'''
                cur.execute(sql, (str(spur_session_data[0]),
                                    str(spur_session_data[1]),
                                    str(spur_session_data[2]),
                                    str(spur_session_data[3]),
                                    str(spur_session_data[4]),
                                    str(spur_session_data[5]),
                                    str(spur_session_data[6]),
                                    str(spur_session_data[7]),
                                    str(spur_session_data[8]),
                                    str(spur_session_data[9]),
                                    str(spur_session_data[10]),
                                    str(spur_session_data[11]),
                                    str(spur_session_data[12]),
                                    str(spur_session_data[13]),
                                    str(spur_session_data[14]),
                                    str(spur_session_data[15]),
                                    str(spur_session_data[16]),
                                    str(spur_session_data[17]),
                                    session, epoch_time))
                con.commit()


        if (attack_type == "abnormal"):
            if (summarizedays):
                report_file = open(date + "_abnormal_" + summarizedays + "-day_report.txt","a", encoding="utf-8")
            else:
                report_file = open(date + "abnormal_report.txt","a", encoding="utf-8")
            report_file.write(attackstring)
            report_file.close()
        else:
            if (summarizedays):
                report_file = open(date + "_" + summarizedays + "_day_report.txt","a", encoding="utf-8")
            else:
                report_file = open(date + "_report.txt","a", encoding="utf-8")
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
    cur = con.cursor()
    commands = ""
    for each_entry in data:
        if each_entry['session'] == session:
            if "cowrie.command.input" in each_entry['eventid']:
                commands += "# " + each_entry['input'] + "\n"
                utc_time = datetime.datetime.strptime(each_entry['timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
                epoch_time = (utc_time - datetime.datetime(1970, 1, 1)).total_seconds()
                sql = '''SELECT * FROM commands WHERE session=? and command=? and timestamp=?'''
                cur.execute(sql, (session, each_entry['input'], epoch_time))
                rows = cur.fetchall()
                if (len(rows) > 0):
                    print("Command data for session " + session + " was already stored within database")
                else:
                    sql = '''INSERT INTO commands(session, command, timestamp, added) VALUES (?,?,?,?)'''
                    #utc_time = datetime.datetime.strptime(each_entry['timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
                    #epoch_time = (utc_time - datetime.datetime(1970, 1, 1)).total_seconds()
                    cur.execute(sql, (session, each_entry['input'], epoch_time, time.time()))
    con.commit()
    return commands

initialize_database()

if len(file_list) == 0: quit()

if (summarizedays):
    days = int(summarizedays)
    print("Days to summarize: " + str(days))
    file_list = []
    i = 0
    while (len(list_of_files) > 0 and (i < days)):
        if (i < days):
            file_list.append(list_of_files.pop())
        i += 1
    list_of_files = file_list

for each_file in list_of_files:
    file_path = log_location + "/" + each_file
    with open(file_path, 'r') as file:
        print("Processing file " + file_path)
        for each_line in file:
            try:
                json_file = json.loads(each_line.replace('\0', ''))
                data.append(json_file)
            except Exception as e:
                logging.error(f"Error parsing data: {e}")
                logging.error(f"Data with error: '{each_line}'")
        file.close()

vt_session = requests.session()
dshield_session = requests.session()
uh_session = requests.session()
spur_session = requests.session()

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

else:    
    session_id = get_session_id(data, "all", "unnecessary")
    print_session_info(data, session_id, "standard")


counts = collections.Counter(number_of_commands)
number_of_commands = sorted(number_of_commands, key=lambda x: -counts[x])
commands = set()
for num_count in number_of_commands:
    commands.add(num_count)

command_number_dict = {}
abnormal_command_counts = []
for command in commands:
    #number of commands --> command
    #number of times the number of commands has been seen --> number_of_commands.count(command)
    command_number_dict[command] = number_of_commands.count(command)

command_number_dict = sorted(command_number_dict.items(), key=lambda x:x[1])
for key, value in command_number_dict:
    abnormal_command_counts.append(key)

abnormal_command_counts = abnormal_command_counts[0:int(len(abnormal_command_counts)*(2/3))]


vt_counts = collections.Counter(vt_classifications)
vt_classifications = sorted(vt_classifications, key=lambda x: -vt_counts[x])
vt_class = set()
for classification in vt_classifications:
    vt_class.add(classification)



if (summarizedays):
    for each_session in session_id:
        command_count = get_command_total(each_session, data)
        #if command_count != number_of_commands[0]:
        if command_count in abnormal_command_counts:
            abnormal_attacks.add(each_session)
            uncommon_command_counts.add(each_session)


elif (session_id):
    sessions = [session_id]
    for each_session in sessions:
        command_count = get_command_total(each_session, data)
        #if command_count != number_of_commands[0]:
        if command_count in abnormal_command_counts:
            abnormal_attacks.add(each_session)
            uncommon_command_counts.add(each_session)

elif (tty_file):
    for each_session in session_id:
        command_count = get_command_total(each_session, data)
        #if command_count != number_of_commands[0]:
        if command_count in abnormal_command_counts:
            abnormal_attacks.add(each_session)
            uncommon_command_counts.add(each_session)


elif (download_file):
    for each_session in session_id:
        command_count = get_command_total(each_session, data)
        #if command_count != number_of_commands[0]:
        if command_count in abnormal_command_counts:
            abnormal_attacks.add(each_session)
            uncommon_command_counts.add(each_session)



vt_session.close()
dshield_session.close()
uh_session.close()
spur_session.close()

summarystring = "{:>40s}  {:10s}".format("Total Number of Attacks:", str(attack_count)) + "\n"
summarystring += "{:>40s}  {:10s}".format("Most Common Number of Commands:", str(number_of_commands[0])) + "\n"
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

if (summarizedays):
    report_file = open(date + "_" + summarizedays + "_day_report.txt","a")
else:
    report_file = open(date + "_report.txt","a")
report_file.write(summarystring)
report_file.close()

if (summarizedays):
    report_file = open(date + "_abnormal_" + summarizedays + "-day_report.txt","a")
else:
    report_file = open(date + "_abnormal_report.txt","a")
report_file.write(summarystring)
report_file.close()
print_session_info(data, abnormal_attacks, "abnormal")

if (dbxapi):
    dbx = dropbox.Dropbox(dbxapi)
    with open(date + "_" + summarizedays + "_day_report.txt", 'rb') as f:
        dbx.files_upload(f.read(), "/" + date + filename_prepend + "_" + summarizedays + "_day_report.txt")

    with open(date + "_abnormal_" + summarizedays + "-day_report.txt", 'rb') as f:
        dbx.files_upload(f.read(), "/" + date + filename_prepend + "_abnormal_" + summarizedays + "-day_report.txt")

    with open("../cowrieprocessor.sqlite", 'rb') as f:
        dbx.files_upload(f.read(), "/" + date + filename_prepend + "_cowrieprocessor.sqlite")

elif (dbxkey and dbxsecret and dbxrefreshtoken):
    dbx = dropbox.Dropbox(
            app_key = dbxkey,
            app_secret = dbxsecret,
            oauth2_refresh_token = dbxrefreshtoken
        )
    with open(date + "_" + summarizedays + "_day_report.txt", 'rb') as f:
        dbx.files_upload(f.read(), "/" + date + filename_prepend + "_" + summarizedays + "_day_report.txt")

    with open(date + "_abnormal_" + summarizedays + "-day_report.txt", 'rb') as f:
        dbx.files_upload(f.read(), "/" + date + filename_prepend + "_abnormal_" + summarizedays + "-day_report.txt")

    with open("../cowrieprocessor.sqlite", 'rb') as f:
        dbx.files_upload(f.read(), "/" + date + filename_prepend + "_cowrieprocessor.sqlite")

else: 
    print("No Dropbox account information supplied to allow upload")

print(summarystring)
con.commit()
