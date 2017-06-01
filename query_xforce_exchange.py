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

engine = create_engine('sqlite:///IP_Report.db')
DBSession = sessionmaker(bind = engine)
session = DBSession()
#Output all downloaded json to a file
output = open(sys.argv[2]+".json","w")
def send_request(apiurl, scanurl, headers,output):
    fullurl = apiurl +  scanurl
    response = requests.get(fullurl, params='', headers=headers, timeout=20)
    all_json = response.json()
    output.write(json.dumps(all_json,indent=4,sort_keys=True))
    return all_json

def get_md5(filename):
    try:
        f = open(filename,"rb")
        md5 = hashlib.md5((f).read()).hexdigest()
        return md5
    except e:
        print str(e)

#This function confirms whether or not an entry already exists. If so, it returns the entry 
def check_ip_exist(Table,Provided_IP):
    while(1):
        count = session.query(Table).filter(Table.IP == Provided_IP).count()
        if count > 0:
            return session.query(Table).filter(Table.IP == Provided_IP).one()
        else:
            new_IP = Table(Score = str("000"),IP = Provided_IP,)
            session.add(new_IP)
            session.commit()
            return 0
#This function will update both current and historic tables for a given column
def update_both_tables(column_number,input_string,Provided_IP):
    columns = ["IP","Location","Date","Score","Category"]
    columner1 = str(columns[column_number])
    
    input_current = session.query(IP_Current).filter(IP_Current.IP == Provided_IP).one()
    setattr(input_current,str(literal_column(str(columner1))),str(input_string))
    session.commit()
    
    input_historic = session.query(IP_History).filter(IP_History.IP == Provided_IP).one()
    setattr(input_historic,str(literal_column(str(columner1))),str(input_string))
    session.commit()
#This function parses the date that comes from the raw JSON output and puts it in a Month/Day/Year format
def date_parse(date_string):
    parsed_date = dateutil.parser.parse(date_string).strftime("%x")
    return parsed_date
#This function pulls current information from JSON output for a handful of keys
def get_current_info(column_number,review_count,Provided_IP,all_json):
    keys = ["categoryDescriptions","created","score"]
    attr = keys[column_number]
    key_count = 0
    if attr == "created" or attr == "score":
        return all_json["history"][review_count-1][attr]
    else:
        for key in all_json["history"][review_count-1][attr]:
            if (key_count >= 1):
                current_info = current_info + " ," + str(key)
            else:
                current_info = str(key)
                key_count += 1
        return current_info

if __name__ == "__main__":
#X-Force API Key and Password associated with your IBMID
    key = "<API_KEY>"
    password ="<API_PASSWORD>"



    Provided_IP = str(sys.argv[2])

    IP_exists = check_ip_exist(IP_Current,Provided_IP)
    IP_exists_history = check_ip_exist(IP_History,Provided_IP)

    token = base64.b64encode(key + ":" + password)
    headers = {'Authorization': "Basic " + token, 'Accept': 'application/json'}
    url = "https://api.xforce.ibmcloud.com:443"


    parser = OptionParser()
    #use this option to check a url
    parser.add_option("-u", "--url", dest="s_url", default="none", 
                      help="url to be checked by exchange ibm xforce", metavar="scanurl")
    #use this option to get malware associated with an entered url
    parser.add_option("-l", "--malwareurl", dest="m_url", default="none", 
                      help="returns the malware associated with the entered url", metavar="scanurl")
    #use this option to check a file's maliciousness
    parser.add_option("-f", "--file", dest="malfile" , default="none",
                      help="file (md5 hash) to be checked by exchange ibm xforce", metavar="filename")
    #use this option to check a md5 hash in general
    parser.add_option("-m", "--md5", dest="hash" , default="none",
                      help="hash to be checked by exchange ibm xforce", metavar="hashvalue")
    #use this option to specify an xfid
    parser.add_option("-x", "--xfid", dest="s_xfid" , default="none",
                      help="xfid to be used ", metavar="xfid")
    parser.add_option("-c", "--cve", dest="s_cve" , default="none",
                      help="cve, bid, us-cert, uv#, rhsa id to be searched ", metavar="cve-xxx-xxx")
    #use this option to check an ip address
    parser.add_option("-i", "--ip", dest="s_ip" , default="none",
                      help="ip to be checked", metavar="ipaddress")
(options, args) = parser.parse_args()

if ( options.s_url is not "none" ):
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
elif (options.s_ip is not "none"):
    scanurl = options.s_ip
    apiurl = url + "/ipr/"
    all_json = send_request(apiurl, scanurl, headers,output)
    apiurl = url + "/ipr/malware/"
    send_request(apiurl, scanurl, headers,output)
    apiurl = url + "/ipr/history/"
    send_request(apiurl, scanurl, headers,output)
elif (options.malfile is not "none" ):
    md5 = get_md5(options.malfile)
    if md5:
        send_request(url+"/malware/", md5, headers,output)
elif (options.s_xfid is not "none" ):
    send_request(url+"/vulnerabilities/", options.s_xfid, headers,output)
elif (options.hash is not "none" ):
    send_request(url+"/ipr/", options.hash, headers,output)
    

#Used to hold categories of an IP or URL that have already been listed in the report.
IP_Location = all_json["geo"]["country"]

#Declarations
already_categorized=[]
current_categories = ""
key_count = 0
category_count = 0
update_both_tables(1,IP_Location,Provided_IP)
review_count = len(all_json['history'])

#For every entry in the json output 
for key in all_json['history']:
 #For every categorization within that entrys "categoryDescriptions"
    for entry in key["categoryDescriptions"]:
 #If this categorization has already been reported, don't report it again
        if(entry in already_categorized):                     
            continue
        else:       #Since we already have this IP in our DB,
            
            update_both_tables(1,IP_Location,Provided_IP)
            
            update_historic_category = session.query(IP_History).filter(IP_History.IP == Provided_IP).one()
            
            record.Score = str(all_json["subnets"][0]["score"])
            session.commit()

            if category_count == 0:   #If this is the first/only categorization for this IP
                record.Category = str(entry)
                category_count += 1
            else:             #Otherwise, make it a nice looking list of categories
                record.Category = str(record.Category) + str(" , ") + str(entry)
                record.Date = date_parse(key["created"])
                session.commit()

            already_categorized.append(entry)   #Add the category to the list of already printed categories so we don't repeat


most_recent = session.query(IP_Current).filter(IP_Current.IP == Provided_IP).one()
most_recent.Date = date_parse(str(get_current_info(1,review_count,Provided_IP,all_json)))   #Adds the latest security check on this IP address to IP_Current Table information
session.commit()

latest_score = session.query(IP_Current).filter(IP_Current.IP == Provided_IP).one()
latest_score.Score = get_current_info(2,review_count,Provided_IP,all_json)        #Adds the latest score that was reported on this IP address to IP_Current Table
session.commit()

latest_categorization = session.query(IP_Current).filter(IP_Current.IP == Provided_IP).one()
latest_categorization.Category = get_current_info(0,review_count,Provided_IP,all_json)   #Adds the latest categorization for this IP address to IP_Current Table
session.commit()

if len(sys.argv[1:]) == 0:
    parser.print_help()


