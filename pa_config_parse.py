## The scripts explore the use of ElementTree to parse and extract policy information from a PA config dump.

import xml.etree.ElementTree as ET

#Insert file name, xml dump
tree = ET.parse('##__file_name__##')
root = tree.getroot()

#print (root.tag)

#for child in root.iter('*'):
#	print (child.tag)

# Find top level tags
#print(root.findall("."))

#To explore through the branches, use the following format, the below shows sub-elements of this branch.
#print(root.findall("./devices/entry/device-group/entry/pre-rulebase/security/rules/*"))

#This type of statement doesn't work,  because findall returns a 'list' rather than a 'element' object
# and a list does not have a 'attribute' child, or a function.
#print(root.findall("./devices/entry/device-group/entry/pre-rulebase/security/rules/*").attrib)

#print(root.findall("./devices/entry/device-group/entry/pre-rulebase/security/rules/*").attrib['name'])

#To iterate over a 'findallesult, which is a list, use a for statemet.
#for i in root.findall("./devices/entry/device-group/entry/pre-rulebase/security/rules/*"):


#This is cool, this specifies to step into '/devices/entry/device-group/entry' branch. There are multiple 'entry' branches at this level.
# The '@name' statement, steps into the entry branch that has a'name=Atrribute_value' attribute!! Vallah!
#Not just that but this expands to show the firewall rules which is under the full path below.
# In the print statement doing 'attrib['name']' prints just the value, else it prints '{'$name', '$value'}'', literally.

#SHOW ALL RULES
#for i in root.findall("./devices/entry/device-group/entry/[@name='##__Insert__DG__##']/pre-rulebase/security/rules/*"):
#	print(i.attrib['name'])

# SHOW RULES WITHOUT SECURITY PROFILES
# The below is used to printout security rules which doesn't have a security profile set. First iterate through all the rules,
# Check each item in the list for 'profile-setting' then do a if to see if the object exists, if there is no profile setting, sec_rule will be none.
'''
for i in root.findall("./devices/entry/device-group/entry/[@name='##__Insert__DG__##']/pre-rulebase/security/rules/*"):
	sec_rule = i.find('profile-setting')
	if sec_rule is None:
		print(i.attrib['name'])
'''		
# Now this checks when there is a profile setting in the child, ie. a IPS profile is setup in the security rule.

#for i in root.findall("./devices/entry/device-group/entry/[@name='##__Insert__DG__##']/pre-rulebase/security/rules/*"):
#	sec_rule = i.find('profile-setting')
#	if sec_rule is not None:
#		print(i.attrib['name'])

#This checks if the rule has a IPS profile, checks if its not disabled, then prints the rule name and IPS profile value
# This code block checks the rulebase for ip profiles and prints out rules that has a profile.
#for i in root.findall("./devices/entry/device-group/entry/[@name='##__Insert__DG__##']/pre-rulebase/security/rules/*"):
#	sec_rule = i".find('profile-setting')
#	if sec_rule is not None:
#		if i.find('disabled') is None:
#			profile = (i.find("./profile-setting/group/member")).text
#			name = i.attrib['name']
#			print(("%s, %s") % (name, profile))


# The problem with the above code is that the xml schema for profile-group is different to using individual profiles.
# So first need to check if the element has a profile group or individual profiles.
# in the below, I'm first checking to see if the rule is disabled


#for i in root.findall("./devices/entry/device-group/entry/[@name='##__Insert__DG__##']/pre-rulebase/security/rules/*"):

#	if i.find('profile-setting') is not None and i.find('disabled') is None:
#	if i.find('profile-setting') is not None:
	#	print (i.attrib['name'])

#		str = i.attrib['name']
#		if i.find(".//profile-setting/group") is not None:
#			str = str + " , Group " +  (i.find("./profile-setting/group/member")).text

#		else:
#			name =  i.attrib['name']
#			str = name
#			for k in i.findall(".//profile-setting/profiles/*"):
#				profile = k.tag
#				profile_value = (k.find("./member")).text
#				str = str + " , " + profile + "=" + profile_value
	
#		if (i.find('disabled') is not None and (i.find('disabled')).text == "no") or i.find('disabled') is None:
#			a = 1
#			if "Group " not in str:
#				print(str)


# SHOWS FIREWALL RULES WITH INDIVIDUAL PROFILES SET
# In this latest iteration, added a second 'find text' in the find group section, because sometimes group is selected but profile is not set!!
# Also added a 'p' switch to stop it from printing the name when not matching ifs, ie name is set in the first str.
# The below is working very slick!!
'''
for i in root.findall("./devices/entry/device-group/entry/[@name='##__Insert__DG__##']/pre-rulebase/security/rules/*"):
	#print(i.attrib['name'])
	p = 0
	if i.find('profile-setting') is not None:
	#	print (i.attrib['name'])

		str = i.attrib['name']
		if i.find(".//profile-setting/group/") is not None:
			if i.find(".//profile-setting/group/").text is not None:
				str = str + " , Group " +  (i.find("./profile-setting/group/member")).text
				p = 1
		else:
			name =  i.attrib['name']
			str = name
			for k in i.findall(".//profile-setting/profiles/*"):
				profile = k.tag
				profile_value = (k.find("./member")).text
				str = str + " , " + profile + "=" + profile_value
				p = 1
	
		if ((i.find('disabled') is not None and (i.find('disabled')).text == "no") or i.find('disabled') is None) and p == 1:
			a = 1
			if "Group " not in str:
				print(str)			

'''
# Get a list of not disabled rules.
'''
count = 0
for i in root.findall("./devices/entry/device-group/entry/[@name='##__Insert__DG__##']/pre-rulebase/security/rules/*"):
	if i.find('disabled') is None:
		count = count + 1
print (count)	
'''

#print ("LOOKING FOR IPS EXEMPTIONS")		
# IPS exemptions have the tag <exept-ip> tag, thus searching below for the tag.
#for i in root.findall("./*"):
#	if i.find("exempt-ip") is not None:
#		print (i.tag)


#Te below checks for tag with a value!!, tag <c> has value 'j'
#tree.xpath("/a/b/c[text()='j']")


#SHOW ALL RULES
#for i in root.findall("./devices/entry/device-group/entry/[@name='##__Insert__DG__##']/pre-rulebase/security/rules/*"):
#	print(i.attrib['name'])

#CHECK FOR A ZONE
'''
for i in root.findall("./devices/entry/device-group/entry/[@name='##__Insert__DG__##']/pre-rulebase/security/rules/*"):
	print(i.attrib['name'])
#	print(i.find("./to/member/").text)
	for j in i.findall("./from/member"):
		print (("From  ==  %s") % (j.text))
	for k in i.findall("./to/member"):
		print (("To  ==  %s") % (k.text))

	#	print (k.text
'''
#for i in root.findall("[from]"):
#	print(i.tag)


# SHOW RULES WITHOUT SECURITY PROFILES
# The below is used to printout security rules which doesn't have a security profile set. First iterate through all the rules,
# Check each item in the list for 'profile-setting' then do a if to see if the object exists, if there is no profile setting, sec_rule will be none.
'''
for i in root.findall("./devices/entry/device-group/entry/[@name='##__Insert__DG__##']/pre-rulebase/security/rules/*"):
	sec_rule = i.find('profile-setting')
	if sec_rule is None:
		print(i.attrib['name'])
'''

# CUSTOM CODE TO MUNGE THROUGH RULES AND LIST OUT UNTRUST RULES AGAINST UNTRUST SECURITY PROFILES
def List_IPS_Profiles(fsite):
	str1 = "./devices/entry/device-group/entry/[@name='" + fsite +"']/pre-rulebase/security/rules/*"
	for i in root.findall(str1):
		zone = "INTERNAL"
		SG = "NONE"
		for j in i.findall("./from/member"):
			if "untrust" == j.text or "any" == j.text:
				zone = "EXTERNAL"
		for k in i.findall("./to/member"):
			if "Untrust" == k.text or "any" == k.text:
				zone = "EXTERNAL"
		if i.find(".//profile-setting/group/") is not None:
			if i.find(".//profile-setting/group/").text is not None:		
				SG = (i.find("./profile-setting/group/member")).text
		if i.find(".//profile-setting/profiles/") is not None:
			SG = "PROFILES"
		str = i.attrib['name'] + "," + zone + "," + SG
		print(str)


#Will filter policy from a certain source zone, and print "rule name, from zone, to zone"
#Removes disabled rules
def Find_Policy(fsite):
	str1 = "./devices/entry/device-group/entry/[@name='" + fsite +"']/pre-rulebase/security/rules/*"
	for i in root.findall(str1):
	#for i in root.findall("./devices/entry/device-group/entry/[@name='##__Insert__DG__##']/pre-rulebase/security/rules/*"):
		for j in i.findall("./from/member"):
			if "Untrust" == j.text or "any" == j.text:
				
				for k in i.findall("./to/member"):
					str2 = i.attrib['name'] + "," + j.text + "," + k.text
					

					if i.find('./disabled') is None:
						print (str2)


#Will filter policy from a certain source zone, and print "rule name, from zone, to zone"
#Find_Policy("##__Insert__DG__##")


def Check_Destinations():

	DC_policies = [ "##__Insert_Policy Name_1__##", "##__Insert_Policy Name_2__##" ]
#	str1 = "./devices/entry/device-group/entry/[@name='" + fsite +"']/pre-rulebase/security/rules/*"
	
	for i in DC_policies:
		str1 = (root.find("./devices/entry/device-group/entry/[@name='##_Device_Group__##']/pre-rulebase/security/rules/entry/[@name='" + i +"']/destination/*")).text
		str2 = "Policy: " + i + " , " + "Dest:" + str1
		print (str2)

#Check_Destinations()


def Check_Services():

	DC_policies = [ "##__Insert_Policy Name_1__##", "##__Insert_Policy Name_2__##" ]
	
	
	for i in DC_policies:
		str1 = "./devices/entry/device-group/entry/[@name='##_Device_Group__##']/pre-rulebase/security/rules/entry/[@name='" + i +"']/service/*"
		str2 = i + ","
		for k in root.findall(str1):
			str2 = str2 + k.text + " "
		print (str2)
	#	print (" ")

Check_Services()
	