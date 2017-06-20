#Miclain Keffeler
#6/6/2017
#This script holds the function needed to generate a CEF (Common Event Format) Event. 
#This can be called when a change is detected between historic and current data.
#A CEF event will then be generated and this can be fed to SIEM software such as HP Arcsight.
import datetime
global is_new_registrar_global 
is_new_registrar_global = 0

global is_new_score_global
is_new_score_global = 0

global is_new_category_global 
is_new_category_global = 0

global is_new_location_global 
is_new_location_global = 0

global is_new_registrar_org_global 
is_new_registrar_org_global = 0

def dynamic_priority(is_new_location,is_new_registrar,is_new_category,is_new_score,old_score,new_score,new_num_categories,old_num_categories):
    net_change = 0
    if(is_new_score == 1):
        net_change = int(new_score) - int(old_score)
        if(1<= net_change <= 2):
            return 5
        elif(3<= net_change <=5):
            return 7
        elif(6<= net_change <= 10):
            return 10
        else:
            return 1
    elif(is_new_location == 1):
        return 2
    elif(is_new__registrar == 1):
        return 3
    elif(is_new_category == 1):
        net_change = 0
        net_change = int(new_num_categories) - int(old_num_categories)
        if(1<= net_change <= 2):
            return 6
        elif(3<= net_change <=5):
            return 10
        elif(6<= net_change <= 10):
            return 10
        else:
            return 1

def dynamic_event_names(Updated_IP,is_new_location,is_new_registrar,new_registrar_name,is_new_category,is_new_score,old_score,new_score,new_num_categories,old_num_categories,new_categories):
    global is_new_registrar_global 
    global is_new_score_global
    global is_new_category_global 
    global is_new_location_global 
    global is_new_registrar_org_global 

    if(is_new_score == 1):
        net_change = int(new_score)-int(old_score)
        if(net_change > 0):
            is_new_score_global = 1
            return "IP Risk Score increased by " + str(net_change)
        else: 
            is_new_score_global = 1
            return "IP Risk Score decreased by " + str(abs(net_change))
    if(is_new_category == 1):
        is_new_category_global = 1
        net_change = int(new_num_categories) - int(old_num_categories)
        if(net_change > 0):
            return "IP Categorization has become " + str(new_categories.replace(',',''))
        if(net_change < 0):
            return "IP Categorization Improvement" 
    if(is_new_location == 1):
        is_new_location_global = 1
        return "IP Geolocation updated to " + str(new_location)
    if(is_new_registrar == 1):
        is_new_registrar_org_global = 1
        return "IP Registered Organization updated to " + str(new_registrar_name)
    else:
        return "Something Changed on IP " + str(Updated_IP)

def did_change(old_string,new_string):
    if(old_string != new_string):
        return 1
    else: 
        return 0

def count_categories(string):
   return string.count(',')


def generate_cef_event(IP_Address,old_registrar_name,old_registrar_org,old_location,old_date,old_score,old_category,new_registrar_name,new_registrar_org,new_location,new_date,new_score,new_category):
    is_new_registrar_global = did_change(old_registrar_name,new_registrar_name)
    message = ""
    event_name = str(dynamic_event_names(IP_Address,did_change(old_location,new_location),did_change(old_registrar_org,new_registrar_org),new_registrar_name,did_change(old_category,new_category),did_change(old_score,new_score),old_score,new_score,count_categories(new_category),count_categories(old_category),new_category))
    if(str(is_new_score_global) == "1"):
        message += "Old score was " + str(old_score) + " New score is now " + str(new_score) + " "
    if(is_new_location_global == 1):
        message += "Old Geolocation was " + str(old_locationd) + "New location is now " + str(new_location) + " "
    if(is_new_category_global == 1):
        message += "Old Categorization/s was " + str(old_category) + " New Categorization/s is now " + str(new_category) + " "
    if(is_new_registrar_global == 1):
        message += "Old Owner was " + str(old_registrar_name) + " New owner is now " + str(new_registrar_name) + " "
    if(is_new_registrar_org_global == 1):
        message += "Old Registered Organization was " + str(old_registrar_org) + " New Organization is now " + str(new_registrar_org) + " "

    cef = 'CEF:0|X-Force|X-Force API|1.0|1.0|' + event_name + '|' + str(dynamic_priority(did_change(old_location,new_location),did_change(old_registrar_org,new_registrar_org),did_change(old_category,new_category),did_change(old_score,new_score),old_score,new_score,count_categories(new_category),count_categories(old_category))) + '|src= ' + str(IP_Address)+ ' end='+ str(datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S:%fZ')) +' msg=' + message
    return cef