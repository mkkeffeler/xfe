#Miclain Keffeler
#6/6/2017 
#This script will update all the entries in both historic and current tables. Pulls the latest JSON file on every IP that is already in tables, and updates entries for that IP and continues for all.
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
from cef_event import generate_cef_event
engine = create_engine('sqlite:///IP_Report.db')
DBSession = sessionmaker(bind = engine)
session = DBSession()
#Output all downloaded json to a file
def send_request(apiurl, scanurl, headers,output):
    fullurl = str(apiurl) +  str(scanurl)
    response = requests.get(fullurl, params='', headers=headers, timeout=20)
    all_json = response.json()
    output = open(output+".json","w")   #Updates the JSON file associated with respective IPs
    output.write(json.dumps(all_json,indent=4,sort_keys=True))
    return all_json

def get_md5(filename):
    try:
        f = open(filename,"rb")
        md5 = hashlib.md5((f).read()).hexdigest()
        return md5
    except e:
        print str(e)

def check_ip_exist(Table,Provided_IP):     #This function confirms whether or not an entry already exists. If so, it returns the entry 
    while(1):
        count = session.query(Table).filter(Table.IP == Provided_IP).count()
        if count > 0:
            return session.query(Table).filter(Table.IP == Provided_IP).one()
        else:
            new_IP = Table(Score = str("000"),IP = Provided_IP)
            session.add(new_IP)
            session.commit()
            return 0

def update_both_tables(column_number,input_string,Provided_IP):             #This function will update both current and historic tables for a given column
    columns = ["IP","Location","Date","Score","Category","registrar_name","registrar_organization"]
    columner1 = str(columns[column_number])
    
    input_current = session.query(IP_Current).filter(IP_Current.IP == Provided_IP).one()   #Updates Current information table
    setattr(input_current,str(literal_column(str(columner1))),str(input_string))
    session.commit()

    input_historic = session.query(IP_History).filter(IP_History.IP == Provided_IP).one()   #Updates Current information table
    setattr(input_historic,str(literal_column(str(columner1))),str(input_string))
    session.commit()


def date_parse(date_string):          #This function parses the date that comes from the raw JSON output and puts it in a Month/Day/Year format

    parsed_date = dateutil.parser.parse(date_string).strftime("%x")
    return parsed_date

def get_current_info(column_number,review_count,Provided_IP,all_json):    #This function pulls current information from JSON output for a handful of keys
    keys = ["categoryDescriptions","created","score"]
    attr = keys[column_number]
    key_count = 0
    current_info = ""
    if attr == "created" or attr == "score":         #If the attribute we are looking for is the created date or score
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
    
    key = "859a8d2b-9d5c-4bfb-957f-6a8ce66d6d04"    #X-Force API Key and Password associated with your IBMID
    password ="ff9e1a26-3c42-4cd2-b764-67e727e6dafd"


    token = base64.b64encode(key + ":" + password)
    headers = {'Authorization': "Basic " + token, 'Accept': 'application/json'}
    url = "https://api.xforce.ibmcloud.com:443"


for IP_Entry in session.query(IP_History).all():      #For every IP address in the IP current table.
    Update_IP = IP_Entry.IP
    apiurl = url + "/ipr/"
    all_json = send_request(apiurl, Update_IP, headers,Update_IP)
    apiurl = url + "/ipr/malware/"
    send_request(apiurl, Update_IP, headers,Update_IP)
    apiurl = url + "/ipr/history/"
    send_request(apiurl, Update_IP, headers,Update_IP)
    apiurl = url + "/whois/"
    whois = send_request(apiurl,Update_IP,headers,Update_IP)   

    IP_Location = all_json["geo"]["country"]             #Used to hold categories of an IP or URL that have already been listed in the report.
    
 
    registrar_name = whois['registrarName']                              #Pull basic whois information on provided IP
    registrar_organization = whois['contact'][0]['organization']

   
    already_categorized=[]                      #Declarations
    current_categories = ""
    key_count = 0
    category_count = 0
    review_count = len(all_json['history'])
    all_categories = ""
    for key in all_json['history']:            #For every entry in the json output 
        for entry in key["categoryDescriptions"]:      #For every categorization within that entrys "categoryDescriptions
            if(entry in already_categorized):               #If this categorization has already been reported, don't report it again
                continue
            else:       #Since we already have this IP in our DB,
            
            
                if category_count == 0:
                    all_categories = str(entry)
                    category_count += 1
                else:
                    all_categories = all_categories + " , " + str(entry)
                    category_count += 1 


                already_categorized.append(entry)   #Add the category to the list of already printed categories so we don't repeat

    if( IP_Entry.Location !=IP_Location): #Checks the latest security check on this IP address to IP_Current Table information
        generate_cef_event(IP_Entry.registrar_name,IP_Entry.registrar_organization,IP_Entry.Location,IP_Entry.Date,IP_Entry.Score,IP_Entry.Category,IP_Location,registrar_name,registrar_organization,date_parse(str(get_current_info(1,review_count,Update_IP,all_json))),get_current_info(2,review_count,Update_IP,all_json),get_current_info(0,review_count,Update_IP,all_json))
        update_both_tables(1,IP_Location,Update_IP)

    if( IP_Entry.Date != date_parse(str(get_current_info(1,review_count,Update_IP,all_json)))): #Checks the latest security check on this IP address to IP_Current Table information
        generate_cef_event(IP_Entry.registrar_name,IP_Entry.registrar_organization,IP_Entry.Location,IP_Entry.Date,IP_Entry.Score,IP_Entry.Category,IP_Location,registrar_name,registrar_organization,date_parse(str(get_current_info(1,review_count,Update_IP,all_json))),get_current_info(2,review_count,Update_IP,all_json),get_current_info(0,review_count,Update_IP,all_json))
        update_both_tables(2,date_parse(str(get_current_info(1,review_count,Update_IP,all_json))),Update_IP)
        print "2"
    if(str(IP_Entry.Score) != str(get_current_info(2,review_count,Update_IP,all_json))):                      #Adds the latest score that was reported on this IP address to IP_Current Table
        generate_cef_event(IP_Entry.registrar_name,IP_Entry.registrar_organization,IP_Entry.Location,IP_Entry.Date,IP_Entry.Score,IP_Entry.Category,IP_Location,registrar_name,registrar_organization,date_parse(str(get_current_info(1,review_count,Update_IP,all_json))),get_current_info(2,review_count,Update_IP,all_json),get_current_info(0,review_count,Update_IP,all_json))
        print IP_Entry.Score
        print get_current_info(2,review_count,Update_IP,all_json)
        update_both_tables(3,get_current_info(2,review_count,Update_IP,all_json),Update_IP) 
        print "32"
        
    if(str(IP_Entry.Category) != get_current_info(0,review_count,Update_IP,all_json)):   #Adds the latest categorization for this IP address to IP_Current Table
        generate_cef_event(IP_Entry.registrar_name,IP_Entry.registrar_organization,IP_Entry.Location,IP_Entry.Date,IP_Entry.Score,IP_Entry.Category,IP_Location,registrar_name,registrar_organization,date_parse(str(get_current_info(1,review_count,Update_IP,all_json))),get_current_info(2,review_count,Update_IP,all_json),get_current_info(0,review_count,Update_IP,all_json))
        update_both_tables(4,all_categories,Update_IP)
        print "##"
    
    if(str(IP_Entry.registrar_organization) != str(registrar_organization)):   #Adds the latest categorization for this IP address to IP_Current Table
        print IP_Entry.registrar_organization
        print registrar_organization     
        generate_cef_event(IP_Entry.registrar_name,IP_Entry.registrar_organization,IP_Entry.Location,IP_Entry.Date,IP_Entry.Score,IP_Entry.Category,IP_Location,registrar_name,registrar_organization,date_parse(str(get_current_info(1,review_count,Update_IP,all_json))),get_current_info(2,review_count,Update_IP,all_json),get_current_info(0,review_count,Update_IP,all_json))
        update_both_tables(6,all_categories,Update_IP)
    
    if(str(IP_Entry.registrar_name) != registrar_name):   #Adds the latest categorization for this IP address to IP_Current Table
        generate_cef_event(IP_Entry.registrar_name,IP_Entry.registrar_organization,IP_Entry.Location,IP_Entry.Date,IP_Entry.Score,IP_Entry.Category,IP_Location,registrar_name,registrar_organization,date_parse(str(get_current_info(1,review_count,Update_IP,all_json))),get_current_info(2,review_count,Update_IP,all_json),get_current_info(0,review_count,Update_IP,all_json))
        update_both_tables(5,all_categories,Update_IP)
        print "3"
 
    session.commit()

print "Updates were Successful"
