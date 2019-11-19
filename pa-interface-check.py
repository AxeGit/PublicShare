## This script prints out interface status (name, mtu, diplex, speed, errors )
## USER INPUTS ##
Firewall_IP = "1.1.1.1"
API_Key = "BLOB"
Interface_List = ["ethernet1/1", "ethernet1/2", "ethernet1/3"] 

import requests
import xml.etree.ElementTree as ET

#These 2 lines help to get rid of SSL warnings for the selfsigned SSL
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning) 

# Provide the API query string for each interface, and returns interface status strings
def check_interfaces(api_string):

	int_name = "NA"
	mtu = "NA"
	duplex = "NA"
	state = "NA"
	speed = "NA"

#Verify = false stops SSL validation error
	r = requests.get(api_string, verify=False)
#	print (r.status_code)
#	print (r.text)

# Setup element tree, from here on for information we navigate the root XML tree.
	root = ET.fromstring(r.content)
#	print(root.findall("."))
#	print (root.text)
#	int_name = root[0][0][2].text 
	
	if root.find('.//error') is None:

		for child in root.iter('name'):
			int_name = child.text
		#	print(child.text)

		for child in root.iter('mtu'):
			mtu = child.text

		for child in root.iter('duplex'):
			duplex = child.text

		for child in root.iter('state'):
			state = child.text

		for child in root.iter('speed'):
			speed = child.text

		log_fwd_errors = root[0][0][6][0][0][1].text
		log_rec_errors = root[0][0][6][0][0][2].text
		hw_rec_errors = root[0][0][6][1][0][5].text

#We only need runtime values, not configured values
		print (("Interface = %s, State = %s, Speed = %s, Duplex = %s, MTU = %s, Logical Forwarding Err = %s, Logical Receive Err = %s, HW Receive Err = %s ") % (int_name, state, speed, duplex, mtu, log_fwd_errors, log_rec_errors, hw_rec_errors))
	else:
		print ("ERROR")

for i in Interface_List:
	api_string = "https://" + Firewall_IP + "/api/?type=op&Key=" + API_Key + "&cmd=<show><interface>" + i + "</interface></show>"
	check_interfaces(api_string)
#	print (api_string)











