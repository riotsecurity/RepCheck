#!/usr/bin/env python3

### CONFIG ####################################################################
# Provide your API keys (as strings) for VirusTotal and AlienVault OTX
# e.g. vt_api = "1234567890"
vt_api = None
otx_api = None
###############################################################################

### INFO ######################################################################
# Author: Timo Sablowski
# Contact: https://www.linkedin.com/in/timo-sablowski
# License: GNU GPLv3 
###############################################################################

import argparse
import sys
import re
import requests
import json
import urllib.parse
import base64

banner = '''
	██████╗ ███████╗██████╗  ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
	██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
	██████╔╝█████╗  ██████╔╝██║     ███████║█████╗  ██║     █████╔╝ 
	██╔══██╗██╔══╝  ██╔═══╝ ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
	██║  ██║███████╗██║     ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
	╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝                                                           
	'''
tool_desc = '''
This tool is used to quickly perform triage for specific targets (IPs, URLs,
hosts or domains). The APIs of VirusTotal and AlienVault OTX are used for this
purpose.
Note:
- The results of VirusTotal only refer to analyses that have already been
  carried out. No new ones are performed!
- The results of AlienVault OTX only show whether there are already pulses
  for the object to be examined. No verdict is queried.
'''

def print_help():
	print(banner)
	print(tool_desc)
	print('''
usage: repcheck.py [-h] [-i ioc] [-I file] [-u] [-b]

Open this python file and define the API keys in the CONFIG section!

options:
  -h, --help  show this help message and exit
  -i ioc      Scan for a single IP, URL, host or domain
  -I file     Provide a file with multiple IPs, URLs, hosts or domains
  -u          Printing only "unclean" results for better clarity
  -b          Remove the banner output. Useful for use within scripts.
''')

parser = argparse.ArgumentParser(prog="repcheck.py", add_help=False)
	#description='''
	#Open this python file and set the API keys in the CONFIG section!
	#''')
parser.add_argument("-i", metavar="ioc")
parser.add_argument("-I", metavar="file")
parser.add_argument("-h", "--help", action="store_true")
parser.add_argument("-u", action="store_true")
parser.add_argument("-b", action="store_true")
args = parser.parse_args()

if args.help == True:
	print_help()
	sys.exit(1)
if args.i and args.I:
		print("Please use only one argument. Type -h for help.")
		sys.exit(1)
if not args.i and not args.I:
		print("Please provide one argument. Type -h for help.")
		sys.exit(1)
if not vt_api and not otx_api:
		print("Provide at least one API key. Open this file and set the variables at the top of the file.")
		sys.exit(1)
if args.u == True:
	unclean_only = True
else:
	unclean_only = False
if args.b == True:
	no_banner = True
else:
	no_banner = False


def get_type(entry):
	'''
	returns the type of the entry:
		ip
		url
		host
		domain
		unknown
	There is no real sanity check if the entry is valid. Just make sure to clean your entry.
	'''
	str(entry)
	if entry.startswith("http"):
		return "url"
	

	entry_parts = entry.split(".")
	if len(entry_parts) < 2:
		# for hosts, IPs or domains the string should contain at least one "."
		return "unknown"
	if len(entry_parts) == 2:
		# If the string can be divided into two parts, this might be a domain
		return "domain"

	# Got the IP regex from here: https://thispointer.com/check-if-a-string-is-a-valid-ip-address-in-python/
	if len(entry_parts) == 4 and re.search( r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", entry):
		return "ip"

	# Everything else might be a hostname
	return "host"

def parse_vt(response_text):
	# Parse the JSON response from VirusTotal and return the count for
	# harmless, malicious, suspicious, undetected
	harmless = None
	malicious = None
	suspicious = None
	undetected = None
	response_dict = json.loads(response_text)
	try:
		harmless = response_dict["data"]["attributes"]["last_analysis_stats"]["harmless"]
	except:
		pass
	try:
		malicious = response_dict["data"]["attributes"]["last_analysis_stats"]["malicious"]
	except:
		pass
	try:
		suspicious = response_dict["data"]["attributes"]["last_analysis_stats"]["suspicious"]
	except:
		pass
	try:
		undetected = response_dict["data"]["attributes"]["last_analysis_stats"]["undetected"]
	except:
		pass
	return harmless, malicious, suspicious, undetected

def parse_otx(response_text):
	# Parse the JSON response from AlienVault and return the count for
	# pulses
	response_dict = json.loads(response_text)
	pulses = response_dict["pulse_info"]["count"]
	return pulses

def get_vt(entry, entry_type):
	# Get the response from VirusTotal in regards to the count for
	# harmless, malicious, suspicious, undetected
	harmless = None
	malicious = None
	suspicious = None
	undetected = None
	entry_url = urllib.parse.quote_plus(entry)
	headers = {'x-apikey': vt_api}
	if entry_type == "ip":
		url = 'https://www.virustotal.com/api/v3/ip_addresses/%s' %(entry_url)
	elif entry_type == "url":
		# see https://developers.virustotal.com/reference/url#url-identifiers
		url_id = base64.urlsafe_b64encode(entry.encode()).decode().strip("=")
		url = 'https://www.virustotal.com/api/v3/urls/%s' %(url_id)
	elif entry_type == "host":
		url = 'https://www.virustotal.com/api/v3/domains/%s' %(entry_url)
	elif entry_type == "domain":
		url = 'https://www.virustotal.com/api/v3/domains/%s' %(entry_url)
	elif entry_type == "unknown":
		return harmless, malicious, suspicious, undetected
	vt_response = requests.get(url, headers=headers)
	if vt_response.status_code == 200:
		try:
			harmless, malicious, suspicious, undetected = parse_vt(vt_response.text)
		except:
			print("Error while parsing the VirusTotal result for %s" %entry)
			pass
	return harmless, malicious, suspicious, undetected


def get_otx(entry, entry_type):
	# Get the response from AlienVault OTX in regards to the amount of pulses
	pulses = None
	entry_url = urllib.parse.quote_plus(entry)
	headers = {'X-OTX-API-KEY': otx_api}
	if entry_type == "ip":
		url = 'https://otx.alienvault.com/api/v1/indicators/IPv4/%s' %(entry_url)
	elif entry_type == "url":
		url = 'https://otx.alienvault.com/api/v1/indicators/url/%s/general' %(entry_url)
	elif entry_type == "host":
		url = 'https://otx.alienvault.com/api/v1/indicators/hostname/%s' %(entry_url)
	elif entry_type == "domain":
		url = 'https://otx.alienvault.com/api/v1/indicators/domain/%s' %(entry_url)
	elif entry_type == "unknown":
		return pulses
	otx_response = requests.get(url, headers=headers)
	if otx_response.status_code == 200:
		try:
			pulses = parse_otx(otx_response.text)
		except:
			print("Error while parsing the AlienVault OTX result for %s" %entry)
			pass
	return pulses

def print_result(entry, entry_type, harmless, malicious, suspicious, undetected, pulses):
	vt_result = "unknown"
	otx_result = "unknown"

	unclean = False

	green = "\033[92m"
	yellow = "\033[93m"
	red = "\033[91m"
	blue = "\033[34m"
	reset_color = "\033[00m"

	if harmless != None and malicious != None and suspicious != None and undetected != None:
		int(harmless)
		int(malicious)
		int(suspicious)
		int(undetected)
		if suspicious > 0:
			vt_result = "%ssuspicious%s" %(yellow, reset_color)
			unclean = True
		if malicious > 1:
			vt_result = "%smalicious%s" %(red, reset_color)
			unclean = True
		if suspicious == 0 and malicious == 0 and harmless > 0:
			vt_result = "%sclean%s" %(green, reset_color)
		if suspicious == 0 and malicious == 0 and harmless == 0 and undetected > 0:
			vt_result = "%sundetected%s" %(blue, reset_color)
	if pulses != None:
		int(pulses)
		if pulses == 0:
			otx_result = "%sclean%s" %(green, reset_color)
		else:
			otx_result = "%ssuspicious%s" %(yellow, reset_color)
			unclean = True


	if entry_type == "unknown":
			vt_result = "unknown"
			otx_result = "unknown"

	if (unclean_only == False) or ((unclean_only == True) and (unclean == True)):
		print("%s\t%s\tVirusTotal: %s\tAlienVault OTX: %s (%s pulses)" %(entry, entry_type, vt_result, otx_result, pulses))

def check_item(item):
	harmless = None
	malicious = None
	suspicious = None
	undetected = None
	pulses = None
	entry = str(item[0])
	entry_type = str(item[1])
	if vt_api:
		harmless, malicious, suspicious, undetected = get_vt(entry, entry_type)
	if otx_api:
		pulses = get_otx(entry, entry_type)
	print_result(entry, entry_type, harmless, malicious, suspicious, undetected, pulses)


#
# Main
#

# Build the array of possible IOCs
to_check = []
if args.i:
	entry_type = get_type(args.i)
	to_check.append([args.i, entry_type])
if args.I:
	try:
		entry_file = open(args.I, 'r').readlines()
	except:
		print("There are problems with opening the provided file.")
		sys.exit(1)
	for line in entry_file:
		entry_type = get_type(line)
		to_check.append([line.strip(), entry_type])

if not no_banner:
	print(banner)
	print(tool_desc)
	print("\n\n")

# Run through the array and check against VT and OTX
if vt_api:
	print("Checking against VirusTotal")
if otx_api:
	print("Checking against AlienVault OTX")
print("\n")
for item in to_check:
	check_item(item)
