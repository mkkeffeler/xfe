#Miclain Keffeler
#6/6/2017
#This script holds the function needed to generate a CEF (Common Event Format) Event. 
#This can be called when a change is detected between historic and current data.
#A CEF event will then be generated and this can be fed to SIEM software such as HP Arcsight.

def generate_cef_event(old_location,old_date,old_score,old_category,new_location,new_date,new_score,new_category):
    print "We will now generate a CEF formatted event"
