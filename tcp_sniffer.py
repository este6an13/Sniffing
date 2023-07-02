from scapy.all import *

# define a function to handle TCP packets
def handle_tcp_packet(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"TCP packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}")

# start the sniffer and filter on TCP packets
sniff(filter="tcp", prn=handle_tcp_packet)
