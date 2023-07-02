from scapy.all import *

def packet_callback(packet):
    if IP in packet and TCP in packet:
        if packet[IP].src == '192.168.0.13' and packet[TCP].dport == 23:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}")

sniff(prn=packet_callback, filter="tcp")
