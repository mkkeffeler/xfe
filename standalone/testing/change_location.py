#Miclain Keffeler
#This script was used to test a change in geolocation for IP address 1.2.3.4. Following this, I ran update_all_ip to generate a CEF event for a change in geolocation


import os
import sys
os.chdir('..')
dirorig = os.getcwd()
sys.path.insert(0, dirorig)
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


engine = create_engine('sqlite:///IP_Report.db')   #Setup the Database
DBSession = sessionmaker(bind = engine)
session = DBSession()   

input_current = session.query(IP_History).filter(IP_Current.IP == sys.argv[1]).one()
setattr(input_current,'Location','harrylair')         #Update current table with new information
session.commit()

