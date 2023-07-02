from scapy.all import *
import time

# Set the target IP address
target_ip = "192.168.0.13"

# Set the source IP address
src_ip = "192.168.0.2"

while True:

    # Create an ICMP packet with an arbitrary value for the ID field
    packet = IP(src=src_ip, dst=target_ip)/ICMP(id=1234)/"Hello World"
    # Send the packet
    send(packet)
    print(f'ICMP packet from {src_ip} to {target_ip}')
    time.sleep(1)
