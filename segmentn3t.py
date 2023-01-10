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
import threading
import time

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

try:
	import ipcalc
except:
	print('[!] ipcalc is not installed. Try "pip install ipcalc"')
	sys.exit(0)

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


class nmapThread(threading.Thread):

	id = None
	name = None
	command = None
	nmap = None

	def __init__(self, threadID, name, ip, arguments):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.name = name
		self.ip = ip
		self.arguments = arguments
		self.nmap = nmap.PortScanner()

	def run(self):
		print("\t\t\t[+] Starting %s at %s" % (self.name, time.ctime(time.time())))
		# func
		self.nmap.scan(hosts=self.ip, arguments=self.arguments)
		print("\t\t\t[-] Exiting %s at %s" % (self.name, time.ctime(time.time())))



def scan(ip, route):
	print("\t\t[!] Scanning %s" % (ip))

	'''
	print("\t\t\t[+] Launching normal.nmap")
	nmScan.scan(hosts=ip, arguments='-Pn -T4 -o %s/normal.nmap' % route)
	print("\t\t\t[+] Launching frag.nmap")
	nmScan.scan(hosts=ip, arguments='-Pn -T4 -f -o %s/frag.nmap' % route)
	print("\t\t\t[+] Launching source53.nmap")
	nmScan.scan(hosts=ip, arguments='-Pn -T4 --source-port 53 -o %s/source53.nmap' % route)
	print("\t\t\t[+] Launching source80.nmap")
	nmScan.scan(hosts=ip, arguments='-Pn -T4 --source-port 80 -o %s/source80.nmap' % route)
	print("\t\t\t[+] Launching source88.nmap")
	nmScan.scan(hosts=ip, arguments='-Pn -T4 --source-port 88 -o %s/source88.nmap' % route)
	print("\t\t\t[+] Launching source443.nmap")
	nmScan.scan(hosts=ip, arguments='-Pn -T4 --source-port 443 -o %s/source443.nmap' % route)
	print("\t\t\t[+] Launching badsum.nmap")
	nmScan.scan(hosts=ip, arguments='-Pn -T4 --badsum -o %s/badsum.nmap' % route)
	print("\t\t\t[+] Launching mtu16.nmap")
	nmScan.scan(hosts=ip, arguments='-Pn -T4 --mtu 16 -o %s/mtu16.nmap' % route)
	print("\t\t\t[+] Launching flag_null.nmap")
	nmScan.scan(hosts=ip, arguments='-Pn -T4 -sN -o %s/flag_null.nmap' % route)
	print("\t\t\t[+] Launching flag_xmas.nmap")
	nmScan.scan(hosts=ip, arguments='-Pn -T4 -sX -o %s/flag_xmas.nmap' % route)
	print("\t\t\t[+] Launching flag_fin.nmap")
	nmScan.scan(hosts=ip, arguments='-Pn -T4 -sF -o %s/flag_fin.nmap' % route)
	print("\t\t\t[+] Launching decoy.nmap")
	nmScan.scan(hosts=ip, arguments='-Pn -T4 -D RND:10 -o %s/decoy.nmap' % route)
	'''
	
	threads = list()
	threads.append( nmapThread(1, 'Normal Nmap', ip, '-n --max-rtt-timeout 2s --max-retries 3 -Pn -T4 -o %s/normal.nmap' % route ) )
	threads.append( nmapThread(2, 'Frag Nmap', ip, '-n --max-rtt-timeout 2s --max-retries 3 -Pn -T4 -f -o %s/frag.nmap' % route ) )
	threads.append( nmapThread(3, 'Source 53 Nmap', ip, '-n --max-rtt-timeout 2s --max-retries 3 -Pn -T4 --source-port 53 -o %s/source53.nmap' % route ) )
	threads.append( nmapThread(4, 'Source 80 Nmap', ip, '-n --max-rtt-timeout 2s --max-retries 3 -Pn -T4 --source-port 80 -o %s/source80.nmap' % route ) )
	threads.append( nmapThread(5, 'Source 88 Nmap', ip, '-n --max-rtt-timeout 2s --max-retries 3 -Pn -T4 --source-port 88 -o %s/source88.nmap' % route ) )
	threads.append( nmapThread(6, 'Source 443 Nmap', ip, '-n --max-rtt-timeout 2s --max-retries 3 -Pn -T4 --source-port 443 -o %s/source443.nmap' % route ) )
	threads.append( nmapThread(7, 'Badsum Nmap', ip, '-n --max-rtt-timeout 2s --max-retries 3 -Pn -T4 --badsum -o %s/badsum.nmap' % route ) )
	threads.append( nmapThread(8, 'MTU Nmap', ip, '-n --max-rtt-timeout 2s --max-retries 3 -Pn -T4 --mtu 16 -o %s/mtu16.nmap' % route ) )
	threads.append( nmapThread(9, 'Flag NULL Nmap', ip, '-n --max-rtt-timeout 2s --max-retries 3 -Pn -T4 -sN -o %s/flag_null.nmap' % route ) )
	threads.append( nmapThread(10, 'Flag XMAS Nmap', ip, '-n --max-rtt-timeout 2s --max-retries 3 -Pn -T4 -sX -o %s/flag_xmas.nmap' % route ) )
	threads.append( nmapThread(11, 'Flag FIN Nmap', ip, '-n --max-rtt-timeout 2s --max-retries 3 -Pn -T4 -sF -o %s/flag_fin.nmap' % route ) )
	threads.append( nmapThread(12, 'Decoy Nmap', ip, '-n --max-rtt-timeout 2s --max-retries 3 -Pn -T4 -D RND:10 -o %s/decoy.nmap' % route ) )

	# Starting threads
	for t in threads:
		t.start()

	print("\t\t\t[+] Launching hgping.txt")
	if '/' in ip:
		for lip in ipcalc.Network(ip):
			os.system("(hping3 --scan 1-7000 -S %s | grep -v 'Not res') 2>> %s" % (lip, route + "/hping.txt"))
	else:
		os.system("(hping3 --scan 1-7000 -S %s | grep -v 'Not res') 2> %s" % (ip, route + "/hping.txt"))
	
	# Waiting threads to finish
	for t in threads:
		t.join()

	print("\t\t[!] Scan of %s finished at %s" % (ip, time.ctime(time.time())))

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
