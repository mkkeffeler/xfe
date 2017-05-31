# xfe
Python API example for IBM X-Force Exchange - https://exchange.xforce.ibmcloud.com/

# IP Address Report 
Added functionality to this report to allow for the creation of a database that stores all the information about an IP address.
Functionality is limited but being improved upon. 
Creates a file named "<IP_ADDRESS_SEARCHED.txt>" with a summary of location and creation date as well as all past categorizations (Malware, Botnet, Spam, etc) and the dates they were classified as such from the history portion of JSON output. Example below.

# Setting Up 
Setting up the database is very simple
`python build_database.py`
This creates a database with 2 tables for Current IP Category and Score and Historic Data. The database is called "IP_Report.db"

# API Query Example
We can now make queries to the X-Force API and the data will be stored for us in the Tables. Be sure to input your own API Key and Password
`python query_xforce_exchange.py -i 1.2.3.4`

This will make an entry for IP address 1.2.3.4 with all the relevant information that came from the JSON Output. This output will be saved to, in this example, "1.2.3.4.json" in case you need to refer to it later. 

Still a work in progress.

# See if it Worked
I created a basic script that will just test to see if there is anything in the Current Table. You can run it as seen below
`python query_completed_database.py`

More functionality is being added to support queries to specific IP's, specific scores, and more.

# More to Come

More functionality being added to support URL queries and more. 
