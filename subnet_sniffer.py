from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(ICMP):
        if packet[IP].src.startswith('168.176.') or packet[IP].dst.startswith('168.176.'):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            print(f"ICMP packet from {src_ip} to {dst_ip}")

sniff(prn=packet_callback, filter="icmp")
