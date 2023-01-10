#!/bin/python3
#
# 	 ____                                  _   _   _ _____ _   
#	/ ___|  ___  __ _ _ __ ___   ___ _ __ | |_| \ | |___ /| |_ 
#	\___ \ / _ \/ _` | '_ ` _ \ / _ \ '_ \| __|  \| | |_ \| __|
#	 ___) |  __/ (_| | | | | | |  __/ | | | |_| |\  |___) | |_ 
#	|____/ \___|\__, |_| |_| |_|\___|_| |_|\__|_| \_|____/ \__|
#	            |___/   
#

import sys,os
from datetime import datetime

try:
	import argparse
except:
	print('[!] argparse is not installed. Try "pip install argparse"')
	sys.exit(0)

try:
	import json
except:
	print('[!] json is not installed. Try "pip install json"')
	sys.exit(0)

try:
	import nmap
except:
	print('[!] nmap is not installed. Try "pip install python-nmap"')
	sys.exit(0)

import ipcalc
'''
try:
	import ipcalc
except:
	print('[!] ipcalc is not installed. Try "pip install ipcalc"')
	sys.exit(0)
'''
#COLOR CODES

BLACK = '\u001b[30m'
RED = '\u001b[31m'
GREEN = '\u001b[32m'
YELLOW = '\u001b[33m'
BLUE = '\u001b[34m'
MAGENTA = '\u001b[35m'
CYAN = '\u001b[36m'
WHITE = '\u001b[37m'
RESET = '\u001b[0m'

#FORMAT CODES
BOLD = '\u001b[1m'
ITALIC = '\u001b[3m'
UNDERLINED = '\u001b[4m'

def banner():

	print('\n\n')
	print('  ____                                  _   _   _ _____ _  ') 
	print(' / ___|  ___  __ _ _ __ ___   ___ _ __ | |_| \ | |___ /| |_ ')
	print(" \___ \ / _ \/ _` | '_ ` _ \ / _ \ '_ \| __|  \| | |_ \| __| ")
	print('  ___) |  __/ (_| | | | | | |  __/ | | | |_| |\  |___) | |_ ')
	print(' |____/ \___|\__, |_| |_| |_|\___|_| |_|\__|_| \_|____/ \__|')
	print('             |___/   ')
	print("\t\t\t\t\tVersion 0.1")
	print("\t\t\t\t\tBy: @mvc1009\n\n")


def print_example():

	print("\n")
	print("[!] Example of a config.json file")
	print('''
[
	{
		"network": "DMZ",
		"subnets": 
		[
			{
				"vlan" : "VLAN7",
				"ip" : "127.0.0.1"

			}

		]
	},
	{
		"network": "FW",
		"subnets": 
		[
			{
				"vlan" : "VLAN73",
				"ip" : "127.0.0.1/30"

			},
			{
				"vlan" : "VLAN72",
				"ip" : "127.0.0.2"

			}

		]
	}
]
		''')
	sys.exit(0)


def scan(ip, route):
	print("\t\t[!] Scanning %s" % (ip))
	nmScan = nmap.PortScanner()
	
	nmScan.scan(hosts=ip, arguments='-Pn -T4 -o %s/normal.nmap' % route)
	
	nmScan.scan(hosts=ip, arguments='-Pn -T4 -f -o %s/frag.nmap' % route)

	nmScan.scan(hosts=ip, arguments='-Pn -T4 --source-port 53 -o %s/source53.nmap' % route)
	nmScan.scan(hosts=ip, arguments='-Pn -T4 --source-port 80 -o %s/source80.nmap' % route)
	nmScan.scan(hosts=ip, arguments='-Pn -T4 --source-port 88 -o %s/source88.nmap' % route)
	nmScan.scan(hosts=ip, arguments='-Pn -T4 --source-port 443 -o %s/source443.nmap' % route)

	nmScan.scan(hosts=ip, arguments='-Pn -T4 --badsum -o %s/badsum.nmap' % route)
	
	nmScan.scan(hosts=ip, arguments='-Pn -T4 --mtu 16 -o %s/mtu16.nmap' % route)

	nmScan.scan(hosts=ip, arguments='-Pn -T4 -sN -o %s/flag_null.nmap' % route)
	nmScan.scan(hosts=ip, arguments='-Pn -T4 -sX -o %s/flag_xmas.nmap' % route)
	nmScan.scan(hosts=ip, arguments='-Pn -T4 -sF -o %s/flag_fin.nmap' % route)

	nmScan.scan(hosts=ip, arguments='-Pn -T4 -D RND:10 -o %s/decoy.nmap' % route)


	if '/' in ip:
		for lip in ipcalc.Network(ip):
			os.system("(hping3 --scan 1-7000 -S %s | grep -v 'Not res') 2>> %s" % (lip, route + "/hping.txt"))
	else:
		os.system("(hping3 --scan 1-7000 -S %s | grep -v 'Not res') 2> %s" % (ip, route + "/hping.txt"))
	

def main():
	
	# Parsing arguments
	parser = argparse.ArgumentParser(description='SegmentN3t is used for internal Segmentation Networks.\n\t\t\n Example: $ python3 segmentn3t.py -i config.json', epilog='Thanks for using me!')
	parser.add_argument('-i', '--input', action='store', dest='finput', help='Input config file')
	parser.add_argument('-pc', '--print-config', action='store_true', help='Print JSON Config File')
	global args
	args =  parser.parse_args()

	# Presentation
	banner()

	#Usage
	if len(sys.argv) < 2:
		parser.print_help()
		sys.exit(0)

	# Print Example Config
	if args.print_config:
		print_example()
	

	# Read Config
	if args.finput:

		with open(args.finput ,'r') as f:
			data = json.load(f)
		
		current_dir = os.getcwd()
		current_dir = os.path.join(current_dir, "results")
		

		date = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
		results_dir = os.path.join(current_dir, date)
		os.mkdir(results_dir)

		print("[!] Saving results in: " + ITALIC + "%s"%(results_dir) + RESET + "\n")

		for i in data:
			
			print(BOLD + UNDERLINED + "[+] Network : %s" % (i['network']) + RESET + "\n")
			network_dir = os.path.join(results_dir, i['network'])
			os.mkdir(network_dir)
			for j in i['subnets']:
				print(BOLD + "\t[+] Subnetwork: %s" % (j['vlan']) + RESET)
				subnetwork_dir = os.path.join(network_dir, j['vlan'])
				os.mkdir(subnetwork_dir)
				scan(j['ip'], subnetwork_dir)
			print("----")

	else:
		parser.print_help()
		sys.exit()





try:
	if __name__ == "__main__":
		main()
except KeyboardInterrupt:
	print("[!] Keyboard Interrupt. Shutting down")
