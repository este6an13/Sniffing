from scapy.all import *

# get the IP address of the default network interface
host_ip = get_if_addr(conf.iface)

print("Host IP address:", host_ip)
