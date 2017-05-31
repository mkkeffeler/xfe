from build_database import IP_Current, IP_History
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base

engine = create_engine('sqlite:///IP_Report.db')
Base = declarative_base()
Base.metadata.bind = engine
from sqlalchemy.orm import sessionmaker
DBSession = sessionmaker(bind = engine)
DBSession.bind = engine
session = DBSession()
# Make a query to find all Persons in the database
# Return the first IP address from all the IP addresses in this table
person = session.query(IP_History).first()
print person.IP

# Find the entry whose IP matches this IP and print their categorizations
code =  session.query(IP_History).filter(IP_History.IP == person.IP).one()
print code.Category
# Retrieve one Address whose person field is point to the person object
 
