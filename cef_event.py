#Miclain Keffeler
#6/6/2017
#This script holds the function needed to generate a CEF (Common Event Format) Event. 
#This can be called when a change is detected between historic and current data.
#A CEF event will then be generated and this can be fed to SIEM software such as HP Arcsight.
import datetime

def generate_cef_event(old_registrar_name,old_registrar_org,old_location,old_date,old_score,old_category,new_registrar_name,new_registrar_org,new_location,new_date,new_score,new_category):
    cef = 'CEF:0|X-Force|X-Force|1.0|1.0|4|end='+str(datetime.datetime.now().strftime('%Y-%m-%DT%H:%M:%S:%fZ'))+' flexnumber1Label="Old_Score" flexnumber1='+str(old_score)+' flexnumber2Label="New_Score" flexnumber2='+str(new_score)    
    print cef

