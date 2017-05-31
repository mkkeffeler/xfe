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
engine = create_engine('sqlite:///IP_Report.db')
DBSession = sessionmaker(bind = engine)
session = DBSession()
#Output all downloaded json to a file
output = open("output.json","w")
outfile = open(sys.argv[2]+".txt","w");
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

if __name__ == "__main__":
#X-Force API Key and Password associated with your IBMID
    key = "<API_KEY>"
    password ="<API_PASSWORD>"


    Provided_IP = str(sys.argv[2])
    while (1):
	#If we do not have a record of this IP in our DB
        if session.query(IP_Current).filter(IP_Current.IP == Provided_IP).count()>0:
            break
        else:
#Otherwise, create a new entry with that IP
            new_IP = IP_Current(Current_Score = str("000"),IP =Provided_IP)
            session.add(new_IP)
            session.commit()
            break

    token = base64.b64encode(key + ":" + password)
    headers = {'Authorization': "Basic " + token, 'Accept': 'application/json'}
    url = "https://api.xforce.ibmcloud.com:443"


    parser = OptionParser()
    #Use this option to check a URL
    parser.add_option("-u", "--url", dest="s_url", default=None, 
                      help="URL to be checked by Exchange IBM Xforce", metavar="scanurl")
    #Use this option to get malware associated with an entered URL
    parser.add_option("-l", "--malwareurl", dest="m_url", default=None, 
                      help="Returns the malware associated with the entered URL", metavar="scanurl")
    #Use this option to check a file's maliciousness
    parser.add_option("-f", "--file", dest="malfile" , default=None,
                      help="file (md5 hash) to be checked by Exchange IBM Xforce", metavar="filename")
    #Use this option to check a md5 hash in general
    parser.add_option("-m", "--md5", dest="hash" , default=None,
                      help="hash to be checked by Exchange IBM Xforce", metavar="hashvalue")
    #Use this option to specify an XFID
    parser.add_option("-x", "--xfid", dest="s_xfid" , default=None,
                      help="XFID to be used ", metavar="xfid")
    parser.add_option("-c", "--cve", dest="s_cve" , default=None,
                      help="CVE, BID, US-Cert, UV#, RHSA id to be searched ", metavar="cve-xxx-xxx")
    #Use this option to check an IP address
    parser.add_option("-i", "--ip", dest="s_ip" , default=None,
                      help="ip to be checked", metavar="ipaddress")
(options, args) = parser.parse_args()

if ( options.s_url is not None ):
    apiurl = url + "/url/"
    scanurl = options.s_url
    all_json = send_request(apiurl, scanurl, headers,output)
elif ( options.m_url is not None ):
    apiurl = url + "/url/malware/" 
    scanurl = options.m_url
    all_json=send_request(apiurl, scanurl, headers,output)
elif ( options.s_cve is not None ):
    apiurl = url + "/vulnerabilities/search/" 
    scanurl = options.s_cve
    all_json = send_request(apiurl, scanurl, headers,output)
elif (options.s_ip is not None):
    scanurl = options.s_ip
    apiurl = url + "/ipr/"
    all_json = send_request(apiurl, scanurl, headers,output)
    apiurl = url + "/ipr/malware/"
    send_request(apiurl, scanurl, headers,output)
    apiurl = url + "/ipr/history/"
    send_request(apiurl, scanurl, headers,output)
elif (options.malfile is not None ):
    md5 = get_md5(options.malfile)
    if md5:
        send_request(url+"/malware/", md5, headers,output)
elif (options.s_xfid is not None ):
    send_request(url+"/vulnerabilities/", options.s_xfid, headers,output)
elif (options.hash is not None ):
    send_request(url+"/ipr/", options.hash, headers,output)
    
#Write the location associated with this IP/URL
outfile.write(all_json["geo"]["country"]+"\n")

#Used to hold categories of an IP or URL that have already been listed in the report.
already_categorized=[]
result_str = ""
create_or_update = 0
#Write the creation date of this IP/URL
outfile.write(all_json['history'][0]['created']+"\n")
#For every entry in the json output 
for key in all_json['history']:
 #For every categorization within that entrys "categoryDescriptions"
    for entry in key["categoryDescriptions"]:
 #If this categorization has already been reported, don't report it again
        if(entry in already_categorized):
            continue
        else:
#IF we already have this IP in our DB or we have just created it 
            if (session.query(IP_History).filter(IP_History.IP == Provided_IP).count()>0) or (create_or_update>0):
                update_category = session.query(IP_History)
                update_category = update_category.filter(IP_History.IP == Provided_IP)
                record = update_category.one() 
                record.Category = record.Category + " " + entry
                session.commit()
            else:
#Create a new entry for this IP Address
                new_historic_info = IP_History(Category= str(entry),Date = str(key["created"]), IP=Provided_IP)
                session.add(new_historic_info)
                session.commit()
                create_or_update += 1
#Write the categorization listed and when it was classified as such
            result_str = result_str + str(entry)+" "+str(key["created"])+" \n" 
    #Add the category to the list of already categorized
            already_categorized.append(entry)
outfile.write(result_str)


if len(sys.argv[1:]) == 0:
    parser.print_help()
