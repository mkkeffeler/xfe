# xfe
Python API example for IBM X-Force Exchange - https://exchange.xforce.ibmcloud.com/

# IP Address Report 
Added functionality to this report to allow for the creation of a database that stores all the information about an IP address.
Functionality is limited but being improved upon. 


# Setting Up 
Setting up the database is very simple  
`python build_database.py`  
This creates a database with 2 tables for Current IP Category and Score and Historic Data. The database is called "IP_Report.db"
## Configuring config.ini
your config.ini file will hold all credentials for XForce and if you have any proxy settings. It also contains setting for the server and port to send CEF Events to when generated. Open the file and it contains directions on what to put where. 

# API Query Example
We can now make queries to the X-Force API and the data will be stored for us in the Tables. Be sure to input your own API Key and Password in the Config.ini
'python query_xforce_exchange.py' Will show the help message. <br><br>
To Add an IP Address to the database please refer to the below:
`python query_xforce_exchange.py -i 1.2.3.4`  

This will make an entry for IP address 1.2.3.4 with all the relevant information that came from the JSON Output. This output will be saved to, in this example, "1.2.3.4.json" in case you need to refer to it later. All JSON output that is retrieved gets stored in subdirectory `IPs/`

The IP_Current table will hold the last time a review was done on this IP and will provide the score it received and its Geolocation.

# See if it Worked
I created a basic script that will just test to see if there is anything in the Current Table. You can run it as seen below  
`python query_completed_database.py --all IP_To_Search`

This will print out all information in both tables on that IP.

# Test CEF Event Generation
There are a few basic use cases that can be exemplified with some testing scripts that have been created. <br>
A few basic use cases include : <br>
1. What happens when 1 characteristic changes in an IP.
2. What happens when multiple changes occur in 1 IP.

You can test this functionality in the direction `testing/`<br>


# More to Come

More functionality being added to support URL queries and more. 
