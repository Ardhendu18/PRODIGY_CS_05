from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        # Check if the packet has a TCP or UDP layer
        if TCP in packet or UDP in packet:
            proto = "TCP" if TCP in packet else "UDP"
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            payload = packet[proto].payload
            
            print(f"Protocol: {proto}")
            print(f"Source IP: {src_ip}")
            print(f"Destination IP: {dst_ip}")
            print(f"Payload: {bytes(payload)}\n")
        else:
            print(f"Protocol: Other IP")
            print(f"Source IP: {ip_layer.src}")
            print(f"Destination IP: {ip_layer.dst}\n")
    else:
        print(f"Packet Type: Non-IP Packet\n")

# Sniff packets with a specified callback function
print("Starting packet capture...")
sniff(prn=packet_callback, filter="ip", store=0)
from scapy.all import sniff, IP, TCP, UDP

