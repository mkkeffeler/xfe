#!/usr/bin/python
__author__='mkkeffeler'

#Miclain Keffeler
#6/6/2017 
#Adds or Updates entries in both the current and historic table on a given IP address. Pulls report from X-Force Exchange API and parses it to a usable format and writes to database.
#Has capability to do other things with x-force but those options have not yet been configured.
#Be sure that 'build_database.py' has been executed prior to running
#Usage: python query_xforce_exchange.py -i <IP>

import requests
import sys
import json
from optparse import OptionParser
import hashlib
import base64
from sqlalchemy import Column, Text, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import types
from build_database import IP_Current, IP_History
from sqlalchemy import exists
import dateutil.parser
from sqlalchemy.sql.expression import literal_column
import os
from configparser import ConfigParser
import getpass


config = ConfigParser()
config.read('config.ini')
key = config.get('DEFAULT', 'KEY')                          #Get API Key and Password from Config.INI file
password = config.get('DEFAULT', 'PASSWORD')

proxies = config.get('DEFAULT','proxies')
if(proxies != ""):
    authuser = str(raw_input('What is the username for Proxy Auth: '))
    authpassword = getpass.getpass('Password for Proxy:')
    auth = authuser + ":" + authpassword
    proxies = {"https": 'http://' + authuser + ':' + authpassword + '@' + proxies}


engine = create_engine('sqlite:///IP_Report.db')   #Setup the Database
DBSession = sessionmaker(bind = engine)
session = DBSession()           #Must be able to query database
os.chdir('xforce/')
output = open(sys.argv[2]+".json","w")    #Output all downloaded json to a file

whois = ""
def send_request(apiurl, scanurl, headers,output):   #This function makes a request to the X-Force Exchange API using a specific URL and headers. 
    fullurl = apiurl +  scanurl
    if(proxies == ""):
        response = requests.get(fullurl, params='',headers=headers, timeout=20)
    else:
        response = requests.get(fullurl, params='',proxies=proxies,headers=headers, timeout=20)
    all_json = response.json()
    output.write(json.dumps(all_json,indent=4,sort_keys=True))
    return all_json

def get_md5(filename):     #This function returns the MD5 hash of a provided file
    try:
        f = open(filename,"rb")
        md5 = hashlib.md5((f).read()).hexdigest()
        return md5
    except e:
        print str(e)

def check_ip_exist(Table,Provided_IP):           #This function confirms whether or not an entry already exists. If so, it returns the entry 
    while(1):
        count = session.query(Table).filter(Table.IP == Provided_IP).count()  
        if count > 0:               #If the entry for this IP exists already (There is 1 occurence of this IP in the table)
            return session.query(Table).filter(Table.IP == Provided_IP).one()
        else:
            new_IP = Table(Score = str("000"),IP = Provided_IP)
            session.add(new_IP)
            session.commit()
            return 0

def update_both_tables(column_number,input_string,Provided_IP):              #This function will update both current and historic tables for a given column
    columns = ["IP","Location","Date","Score","Category","registrar_name","registrar_organization"]
    columner1 = str(columns[column_number])
    
    input_current = session.query(IP_Current).filter(IP_Current.IP == Provided_IP).one()
    setattr(input_current,str(literal_column(str(columner1))),str(input_string))         #Update current table with new information
    session.commit()
    
    input_historic = session.query(IP_History).filter(IP_History.IP == Provided_IP).one()
    setattr(input_historic,str(literal_column(str(columner1))),str(input_string))   #Update historic table with new information
    session.commit()

def date_parse(date_string):                          #This function parses the date that comes from the raw JSON output and puts it in a Month/Day/Year format
    parsed_date = dateutil.parser.parse(date_string).strftime("%x")
    return parsed_date

def get_current_info(column_number,review_count,Provided_IP,all_json):             #This function pulls current information from JSON output for a handful of keys
 
    keys = ["categoryDescriptions","created","score"]
    attr = keys[column_number]                              #Declarations
    key_count = 0
    current_info = ""

    if attr == "created" or attr == "score":   #If the attribute we are looking for is the created date or score
        return all_json["history"][review_count-1][attr]
    else:
        for key in all_json["history"][review_count-1][attr]:  #For every report except the most recent report (Which is current, not history)
            if (key_count >= 1):
                current_info = current_info + " ," + str(key)
            else:
                current_info = str(key)
                key_count += 1
        return current_info

if __name__ == "__main__":
    
    Provided_IP = str(sys.argv[2])

    IP_exists = check_ip_exist(IP_Current,Provided_IP)              #Check if the IP provided exists in the table already. If so, they we don't need to create another entry
    IP_exists_history = check_ip_exist(IP_History,Provided_IP)

    token = base64.b64encode(key + ":" + password)
    print token
    headers = {'Authorization': "Basic " + token, 'Accept': 'application/json'}
    url = "https://api.xforce.ibmcloud.com:443"


    parser = OptionParser()
    parser.add_option("-u", "--url", dest="s_url", default="none", 
                      help="url to be checked by exchange ibm xforce", metavar="scanurl")                 #Use this option to check a url
    parser.add_option("-l", "--malwareurl", dest="m_url", default="none", 
                      help="returns the malware associated with the entered url", metavar="scanurl")               #Use this option to get malware associated with a url
    parser.add_option("-f", "--file", dest="malfile" , default="none",
                      help="file (md5 hash) to be checked by exchange ibm xforce", metavar="filename")                 #Use this option to check a file's maliciousness
    parser.add_option("-m", "--md5", dest="hash" , default="none",
                      help="hash to be checked by exchange ibm xforce", metavar="hashvalue")                       #use this option to check a md5 hash
    parser.add_option("-x", "--xfid", dest="s_xfid" , default="none",
                      help="xfid to be used ", metavar="xfid")                                  #Use this option to specify an xfid
    parser.add_option("-c", "--cve", dest="s_cve" , default="none",
                      help="cve, bid, us-cert, uv#, rhsa id to be searched ", metavar="cve-xxx-xxx")
    parser.add_option("-i", "--ip", dest="s_ip" , default="none",
                      help="ip to be checked", metavar="ipaddress")                                           #Use this option to check an IP address
(options, args) = parser.parse_args()

if ( options.s_url is not "none" ): #If the -u option was used, then take the value that was entered for that parameter and 
    apiurl = url + "/url/"
    scanurl = options.s_url
    all_json = send_request(apiurl, scanurl, headers,output)
elif ( options.m_url is not "none" ):
    apiurl = url + "/url/malware/" 
    scanurl = options.m_url
    all_json=send_request(apiurl, scanurl, headers,output)
elif ( options.s_cve is not "none" ):
    apiurl = url + "/vulnerabilities/search/" 
    scanurl = options.s_cve
    all_json = send_request(apiurl, scanurl, headers,output)
elif (options.s_ip is not "none"):    #If the -i option was used
    scanurl = options.s_ip
    apiurl = url + "/ipr/"
    all_json = send_request(apiurl, scanurl, headers,output)
    apiurl = url + "/ipr/malware/"
    send_request(apiurl, scanurl, headers,output)
    apiurl = url + "/ipr/history/"
    send_request(apiurl, scanurl, headers,output)
    apiurl = url + "/whois/"
    whois = send_request(apiurl,scanurl,headers,output)
elif (options.malfile is not "none" ):
    md5 = get_md5(options.malfile)
    if md5:
        send_request(url+"/malware/", md5, headers,output)
elif (options.s_xfid is not "none" ):
    send_request(url+"/vulnerabilities/", options.s_xfid, headers,output)
    
elif (options.hash is not "none" ):
    send_request(url+"/ipr/", options.hash, headers,output)
    

IP_Location = all_json["geo"]["country"]     #Used to hold categories of an IP or URL that have already been listed in the report.

already_categorized=[]
current_categories = ""
key_count = 0                                           #Declarations
category_count = 0
update_both_tables(1,IP_Location,Provided_IP)
review_count = len(all_json['history'])

registrar_name = whois['registrarName']                              #Pull basic whois information on provided IP
registrar_organization = whois['contact'][0]['organization']

for key in all_json['history']:    #For every entry in the json output 
    for entry in key["categoryDescriptions"]:         #For every categorization within that entrys "categoryDescriptions"
        if(entry in already_categorized):                               #If this categorization has already been reported, don't report it again
            continue
        else:       #Since we already have this IP in our DB,
            
            update_both_tables(1,IP_Location,Provided_IP)
            
            update_historic_category = session.query(IP_History).filter(IP_History.IP == Provided_IP).one()
            if category_count == 0:    #If this is the first categorization that has been assigned to this IP
                update_historic_category.Category = str(entry)
                category_count += 1
            else:   #Otherwise we need commas and to keep what was already in there
                update_historic_category.Category = update_historic_category.Category + " , " + str(entry)
                category_count += 1 
            session.commit()


            already_categorized.append(entry)   #Add the category to the list of already printed categories so we don't repeat

update_both_tables(5,str(registrar_name),Provided_IP)             #Add the registrar name to this IP address in both tables

update_both_tables(6,str(registrar_organization),Provided_IP)             #Add the registrar organization to this IP in both tables

update_both_tables(2,date_parse(str(get_current_info(1,review_count,Provided_IP,all_json))),Provided_IP)   #Adds the latest security check on this IP address to IP_Current Table information

update_both_tables(3,get_current_info(2,review_count,Provided_IP,all_json),Provided_IP)        #Adds the latest score that was reported on this IP address to IP_Current Table

update_both_tables(4,get_current_info(0,review_count,Provided_IP,all_json),Provided_IP)   #Adds the latest categorization for this IP address to IP_Current Table

if len(sys.argv[1:]) == 0:
    parser.print_help()


