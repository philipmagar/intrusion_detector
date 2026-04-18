from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

# Store IP activity
ip_activity = defaultdict(list)

THRESHOLD = 10  # number of ports
TIME_WINDOW = 10  # seconds


def detect_port_scan(ip):
    ports = ip_activity[ip]
    
    # Remove old timestamps
    current_time = time.time()
    ip_activity[ip] = [t for t in ports if current_time - t < TIME_WINDOW]

    if len(ip_activity[ip]) > THRESHOLD:
        print(f"[ALERT] Possible port scan detected from {ip}")


def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        
        # Record timestamp
        ip_activity[src_ip].append(time.time())

        detect_port_scan(src_ip)

        print(packet.summary())


print("Starting IDS...")

sniff(prn=process_packet, store=False)
