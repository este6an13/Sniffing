from scapy.all import *

# define a function to handle ICMP packets
def handle_icmp_packet(packet):
    if packet.haslayer(ICMP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"ICMP packet from {src_ip} to {dst_ip}")

# start the sniffer and filter on ICMP packets
sniff(filter="icmp", prn=handle_icmp_packet)
