#Miclain Keffeler
#Same as change_location. This script changes the risk Score of IP address 1.2.3.4. Followed up update_all_ip, a CEF event will be generated noting the changed score.

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
setattr(input_current,'Score','5')         #Update current table with new information
session.commit()

