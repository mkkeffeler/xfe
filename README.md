# xfe
Python API example for IBM X-Force Exchange - https://exchange.xforce.ibmcloud.com/

#IP Address Report 
Added functionality to this report to allow for the compiling of JSON output in a human readable format.
Creates a file named "<IP_ADDRESS_SEARCHED.txt>" with a summary of location and creation date as well as all past categorizations (Malware, Botnet, Spam, etc) and the dates they were classified as such from the history portion of JSON output. Example below.

#IP Address Query Example
You can make a query to the X-Force API through the following command. Be sure to input your own API Key and Password
`python query_xforce_exchange.py -i 1.2.3.4`

"1.2.3.4" represents the IP address you want to get a report on. This will then check that IP address against all the information the X-Force API has and will return the JSON file with all relevant information to you. This output will be saved to "output.json" in case you need to refer to it later. 

A file will be created named "1.2.3.4.txt". I just ran it and the following was the output I received: 
Australia
2012-03-22T07:26:00.000Z
Anonymisation Services 2012-04-21T23:42:00.000Z
Malware 2012-04-26T09:30:00.000Z
Botnet Command and Control Server 2014-06-02T09:50:00.000Z
Spam 2016-07-18T14:16:00.000Z
Scanning IPs 2016-08-04T14:50:00.000Z

This summarizes all past categorizations of this IP address and provides its known Geolocation as well as date of creation.


#More to Come


More functionality being added to support URL queries and more. 
