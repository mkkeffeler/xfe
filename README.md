# xfe
Python API example for IBM X-Force Exchange - https://exchange.xforce.ibmcloud.com/

# Setting Up the Standalone Database and Query
## Within the Standalone Directory 
Setting up the database is very simple  
First install all requirements<br>
`pip install -r requirements.txt` 
<br>
Now it becomes very easy to setup your database,<br>
`python build_database.py`
  
This creates a database with 2 tables for Current IP Category and Score and Historic Data on the same IP addresses. The database is called "IP_Report.db".
### Config.ini Setings
Within the config.ini file, both the KEY and PASWORD should be set to your provided X-Force API Key and Password. Instruction on obtaining a Key:Password Combo can be obtained here: [X-Force Authentication Instructions](https://api.xforce.ibmcloud.com/doc/#auth). The HOST and PORT settings are for running the Update_all_ip.py script which generates and sends CEF Formatted events to the provided hostname and port. More information on this script can be found below. 
#### Proxy Settings
If the 'proxies' entry in the config.ini file is empty, all the scripts within the standalone version will reach out to X-Force without prompting for Proxy Authentication. However, if an entry does exist in the config.ini file (I.e 'proxies = proxy.mycompany.com') then all the scripts will prompt for a username and password when authenticating to the provided proxy. Clarification on how to enter your proxy settings are commented in the file.

# API Query Example
We can now make queries to the X-Force API and the data will be stored for us in the Database. Be sure to input your own API Key and Password in the config.ini file. Refer to the config.ini section in this document for more information.
<br> Once everything is setup in your config.ini file you can do the below:<br>
`python query_xforce_exchange.py -i 1.2.3.4`  

This will make an entry for IP address 1.2.3.4 with all the relevant information that came from the JSON Output. This output will be saved to, in this example, "1.2.3.4.json" in case you need to refer to it later for errors or checking. 

The IP_Current table will hold the last time a review was done on this IP and will provide the score it received and its Geolocation, amongst all other categorizations at that time.

# See if it Worked
I created a basic script that will just test to see if there is anything in the Current Table. You can run it as seen below  
`python query_completed_database.py --all IP`

This will print out all information in both tables on that IP. Other options are being built but none are working as of now.

More functionality is being added to support queries to specific scores and more.

# Test CEF Event Generation
Within the subdirectory /standalone/testing are 2 scripts. `change_location.py` and `change_score.py` will change the geolocation and score of a provided IP address in the IP_History table, respectively. Then, when `python update_all_ip.py` is executed, a CEF event for those changes will be generated. You will be able to generate single events, as well as multiple events at one time to confirm that things are working as planned. Usage of test scripts is as follows:<br>
`python change_location.py <IP_TO_CHANGE>`<br>
`python change_score.py <IP_TO_CHANGE>`<br>
***Please note, the IP address you are wishing to change must already have been executed with the query_xforce_exchange.py script in order to work properly.***

# Update your Database
To update your database and check against the newest information on X-Force, simply run `python update_all_ip.py`. <br><br> This will pull the latest updates for all IP addresses in the database currently, and generate CEF events for everything that has changed. Dynamic event naming and priority ranking systems are built in. 

# More to Come

More functionality being added to support URL queries and more. Working on setuping a pypi package that can be installed and contains the above functionality through methods
