from scapy.layers.inet import IP
from scapy.all import sniff

#Callback function to process captured packets
def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip}\tDestination IP: {dst_ip}")

#Sniff packets on the "br0" interface in promiscuous mode
sniff(iface="br0", prn=process_packet, filter="ip")
