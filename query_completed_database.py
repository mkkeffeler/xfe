from build_database import IP_Current, IP_History
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from optparse import OptionParser
import sys
engine = create_engine('sqlite:///IP_Report.db')
Base = declarative_base()
Base.metadata.bind = engine
from sqlalchemy.orm import sessionmaker
DBSession = sessionmaker(bind = engine)
DBSession.bind = engine
session = DBSession()
# Make a query to find all Persons in the database

columns = ["IP","Location","Date","Score","Category"]
# Retrieve one Address whose person field is point to the person object
# Return the first IP address from all the IP addresses in this table


# Find the entry whose IP matches this IP and print their categorizations
def print_ip(string):
    print "IP: " + string

def print_location(string):
    print "Location: " + string

def print_date(string):
    print "Date of Review: " + string

def print_score(string):
    print "Score: " + string

def print_category(string):
    print "All Current Categorizations: " + string

def print_historic_category(string):
    print "All Historic Categorizations: " + string

if __name__ == "__main__":
    parser = OptionParser()
    #use this option to check a url
    parser.add_option("--all1", "--all", dest="all1", default="none",  
                      help="Print all columns of a provided IP, must provide IP with -i", metavar="all")
    #use this option to get malware associated with an entered url
    parser.add_option("--current", "--current", dest="current", default="none", 
                      help="returns IPs with matching current categories, must provide -category and -i", metavar="current")
    #use this option to check a file's maliciousness
    parser.add_option("--category", "--category", dest="category" , default="none",
                      help="Category to be checked against provided IP", metavar="category")
    #use this option to check an ip address
    parser.add_option("-i", "--ip", dest="ip" , default="none",
                      help="ip to be checked in database", metavar="ipaddress")
(options, args) = parser.parse_args()

if options.all1 is not "None":
    person = session.query(IP_Current).filter(IP_Current.IP == options.all1).one()
    print "Current Information"
    print_ip(person.IP)
    print_location(person.Location)
    print_date( person.Date)
    print_score( person.Score)
    print_category( person.Category)
    current = session.query(IP_History).filter(IP_History.IP == options.all1).one()
    print "\nHistoric Information\n"
    print_ip(current.IP)
    print_location(current.Location)
    print_date(current.Date)
    print_score(current.Score)
    print_historic_category(current.Category)
if len(sys.argv[1:]) == 0:
    parser.print_help()
