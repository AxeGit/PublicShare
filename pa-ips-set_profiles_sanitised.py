#THIS SCRIPT CAB BE USED TO DELETE SECURITY GROUPS OR SET SECURITY GROUPS FROM A PROVIDED SET OF RULES ON PANORAMA.
#SET THE LOGIN DETAILS AND RULES LIST IN THE 'USER INPUT' SECTION. SET THE SECURITY GROUP IN THE RUN BOOK SECTION AT THE BOTTOM.
#NOTE THE DEVICE-GROUP STRING IS HARD CODED, SO PLEASE CHANGE IT IN CODE. WILL MIGRATE TO USER SECTION IN THE NEXT UPDATE.

## USER INPUTS ##
Firewall_IP = "192.168.1.1"
API_Key = "BLOB"



#Populate with rules in the list for setting or deleting profiles.
Set_Rules_List =  [ "__" ]
Delete_Rules_List = [ "__" ]


## CODE ##

import requests
import xml.etree.ElementTree as ET

#These 2 lines help to get rid of SSL warnings for the selfsigned SSL
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning) 


def exec_req(fapi_string):
	r = requests.get(fapi_string, verify=False)	
	print (r.status_code)
	print (r.text)


# Insert device group
def set_IPS(frule_name, fSG):
	API_type = ""
	api_xpath = "&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='#_DG_NAME#']/pre-rulebase/security/rules/entry[@name='" + frule_name + "']/profile-setting/group"
	api_element = "&element=<member>" + fSG + "</member>"
	api_string = "https://" + Firewall_IP + "/api/?Key=" + API_Key + "&type=config&action=set" + api_xpath + api_element
	print (api_string)
	exec_req(api_string)

#Insert Threat Prevention Group for deletion
def delete_IPS(frule_name):
	API_type = ""
	api_xpath = "&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='#_DG_NAME#']/pre-rulebase/security/rules/entry[@name='" + frule_name + "']/profile-setting"
	api_element = "&element=<member>#__TP_GROUP_NAME__#</member>"
	api_string = "https://" + Firewall_IP + "/api/?Key=" + API_Key + "&type=config&action=delete" + api_xpath
	print (api_string)
	exec_req(api_string)

def exec_req(fapi_string):
	r = requests.get(fapi_string, verify=False)	
	print (r.status_code)
	print (r.text)



##RUN BOOK##

#1. Delete existing SG's.
for i in Delete_Rules_List:
	delete_IPS(i)

#2. Apply Rule SG's
for i in Set_Rules_List:
	set_IPS(i, "##TP_PROFILE_GROUP_NAME##")





























