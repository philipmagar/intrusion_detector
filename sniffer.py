import json
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

# Store IP activity
ip_activity = defaultdict(list)
connection_attempts = defaultdict(int)

THRESHOLD = 10
TIME_WINDOW = 10


def log_alert(ip, alert_type):
    log_entry = {
        "ip": ip,
        "type": alert_type,
        "time": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    with open("alerts.jsonl", "a") as f:
        f.write(json.dumps(log_entry) + "\n")


def detect_port_scan(ip):
    ports = ip_activity[ip]

    current_time = time.time()
    ip_activity[ip] = [t for t in ports if current_time - t < TIME_WINDOW]

    if len(ip_activity[ip]) > THRESHOLD:
        print(f"[ALERT] Port scan detected from {ip}")
        log_alert(ip, "Port Scan")


def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src

        # Port scan tracking
        ip_activity[src_ip].append(time.time())
        detect_port_scan(src_ip)

        # Brute force detection
        connection_attempts[src_ip] += 1

        if connection_attempts[src_ip] > 20:
            print(f"[ALERT] Possible brute-force attack from {src_ip}")
            log_alert(src_ip, "Brute Force")

        print(packet.summary())


print("Starting IDS...")

sniff(prn=process_packet, store=False)
