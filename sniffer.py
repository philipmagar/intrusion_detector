"""
Network Traffic Sniffer & Real-Time Intrusion Detection Engine.

Captures live network packets via Scapy (or generates realistic simulated security attack scenarios),
normalizes them into standardized SecurityEvents, evaluates them through modular detectors,
logs alerts to local JSON/JSONL, maintains real-time in-memory cache, and exports structured JSON reports.
"""

import os
import sys
import time
import random
from typing import Optional

from packet_parser import packet_to_security_event, SecurityEvent
from alert_manager import AlertManager, global_alert_manager
from engine import IntrusionDetectorEngine
from detectors.base import DetectionResult

try:
    from scapy.all import sniff
except ImportError:
    sniff = None


def print_alert(result: DetectionResult, alert_record: dict):
    """Callback triggered whenever an attack is detected by any detector module."""
    severity = result.severity
    rule = result.triggered_rule
    conf = f"{int(result.confidence * 100)}%"
    src = alert_record.get("src_ip", "UNKNOWN")
    dst = alert_record.get("dst_ip", "UNKNOWN")
    
    print("\n" + "=" * 80)
    print(f"[ALERT: {result.attack_type.upper()}] Severity: {severity} | Confidence: {conf}")
    print(f"Rule: {rule}")
    print(f"Attacker: {src} -> Target: {dst}")
    print(f"Details: {result.evidence.get('details')}")
    print(f"Stats: {result.evidence.get('packet_stats')}")
    print("=" * 80 + "\n")


# Global engine instance with alert logging callback
ids_engine = IntrusionDetectorEngine(
    alert_manager=global_alert_manager,
    on_alert_callback=print_alert
)


def log_alert(ip: str, alert_type: str, event: Optional[SecurityEvent] = None):
    """
    Backwards compatibility helper for external or legacy callers.
    """
    res = DetectionResult(
        attack_type=alert_type,
        severity="MEDIUM",
        confidence=0.80,
        triggered_rule="RULE_LEGACY_GENERIC",
        evidence={
            "src_ip": ip,
            "dst_ip": event.dst_ip if event else None,
            "details": f"Legacy alert: {alert_type} from {ip}",
            "packet_stats": {"packet_size": event.packet_size if event else 0}
        },
        timestamp=event.timestamp if event else time.strftime("%Y-%m-%d %H:%M:%S")
    )
    global_alert_manager.record_alert(res, event=event)


def process_packet(packet):
    """
    Processes incoming Scapy packet, converts it into a standardized security event,
    and runs anomaly/threat detection heuristics.
    """
    event = packet_to_security_event(packet)

    if not event.src_ip:
        return

    # Pass through modular detection pipeline
    alerts = ids_engine.process_event(event)

    # Standardized packet stream line
    flags_info = f" Flags=[{event.flags}]" if event.flags else ""
    port_info = f" {event.src_port}->{event.dst_port}" if event.src_port or event.dst_port else ""
    alert_badge = f" [ALERT: {alerts[0].attack_type}]" if alerts else ""
    print(f"[{event.timestamp}] {event.protocol}{port_info}{flags_info} | {event.src_ip} -> {event.dst_ip} ({event.packet_size}B){alert_badge}")


def start_mock_traffic():
    """
    Simulates realistic multi-vector security traffic targeting the modular detectors:
    - Vertical Port Scans
    - TCP SYN Floods
    - SSH/RDP Brute Force
    - Xmas / Null Scan Evasions
    - ICMP / UDP Floods
    """
    print("Starting Mock IDS Attack Simulation Engine...")
    print("Simulating live threat scenarios into detection pipeline...\n")

    scenarios = [
        "PORT_SCAN",
        "SYN_FLOOD",
        "SSH_BRUTE_FORCE",
        "XMAS_SCAN",
        "NULL_SCAN",
        "ICMP_FLOOD",
        "BENIGN_TRAFFIC",
    ]

    attacker_ips = ["192.168.1.105", "10.0.0.99", "172.16.5.42", "203.0.113.88"]
    target_servers = ["192.168.1.1", "10.0.0.1", "172.16.5.10"]

    try:
        while True:
            scenario = random.choice(scenarios)
            attacker = random.choice(attacker_ips)
            target = random.choice(target_servers)
            now_epoch = time.time()
            now_str = time.strftime("%Y-%m-%d %H:%M:%S")

            if scenario == "PORT_SCAN":
                print(f"[SIMULATION] Initiating Vertical Port Scan from {attacker} -> {target}")
                ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]
                for p in ports:
                    evt = SecurityEvent(
                        src_ip=attacker,
                        dst_ip=target,
                        src_port=random.randint(40000, 60000),
                        dst_port=p,
                        protocol="TCP",
                        packet_size=60,
                        flags="SYN",
                        flags_list=["SYN"],
                        timestamp=now_str,
                        timestamp_epoch=time.time(),
                        summary=f"TCP {attacker} -> {target}:{p} [SYN]"
                    )
                    ids_engine.process_event(evt)
                    time.sleep(0.05)

            elif scenario == "SYN_FLOOD":
                print(f"[SIMULATION] Initiating TCP SYN Flood from {attacker} -> {target}:80")
                for _ in range(30):
                    evt = SecurityEvent(
                        src_ip=attacker,
                        dst_ip=target,
                        src_port=random.randint(1024, 65535),
                        dst_port=80,
                        protocol="TCP",
                        packet_size=54,
                        flags="SYN",
                        flags_list=["SYN"],
                        timestamp=now_str,
                        timestamp_epoch=time.time(),
                        summary=f"TCP {attacker} -> {target}:80 [SYN]"
                    )
                    ids_engine.process_event(evt)
                    time.sleep(0.02)

            elif scenario == "SSH_BRUTE_FORCE":
                print(f"[SIMULATION] Initiating SSH Brute Force from {attacker} -> {target}:22")
                for _ in range(15):
                    evt = SecurityEvent(
                        src_ip=attacker,
                        dst_ip=target,
                        src_port=random.randint(40000, 60000),
                        dst_port=22,
                        protocol="TCP",
                        packet_size=120,
                        flags="PSH+ACK",
                        flags_list=["PSH", "ACK"],
                        timestamp=now_str,
                        timestamp_epoch=time.time(),
                        summary=f"TCP {attacker} -> {target}:22 [SSH Auth Attempt]"
                    )
                    ids_engine.process_event(evt)
                    time.sleep(0.08)

            elif scenario == "XMAS_SCAN":
                print(f"[SIMULATION] Injecting TCP Xmas Scan packet from {attacker} -> {target}:80")
                evt = SecurityEvent(
                    src_ip=attacker,
                    dst_ip=target,
                    src_port=54321,
                    dst_port=80,
                    protocol="TCP",
                    packet_size=60,
                    flags="FIN+PSH+URG",
                    flags_list=["FIN", "PSH", "URG"],
                    timestamp=now_str,
                    timestamp_epoch=time.time(),
                    summary=f"TCP {attacker} -> {target}:80 [FIN+PSH+URG]"
                )
                ids_engine.process_event(evt)

            elif scenario == "NULL_SCAN":
                print(f"[SIMULATION] Injecting TCP Null Scan packet from {attacker} -> {target}:443")
                evt = SecurityEvent(
                    src_ip=attacker,
                    dst_ip=target,
                    src_port=54322,
                    dst_port=443,
                    protocol="TCP",
                    packet_size=60,
                    flags=None,
                    flags_list=[],
                    timestamp=now_str,
                    timestamp_epoch=time.time(),
                    summary=f"TCP {attacker} -> {target}:443 [NULL]"
                )
                ids_engine.process_event(evt)

            elif scenario == "ICMP_FLOOD":
                print(f"[SIMULATION] Initiating ICMP Ping Flood from {attacker} -> {target}")
                for _ in range(25):
                    evt = SecurityEvent(
                        src_ip=attacker,
                        dst_ip=target,
                        src_port=None,
                        dst_port=None,
                        protocol="ICMP",
                        packet_size=84,
                        flags=None,
                        flags_list=None,
                        timestamp=now_str,
                        timestamp_epoch=time.time(),
                        summary=f"ICMP {attacker} -> {target} Echo Request"
                    )
                    ids_engine.process_event(evt)
                    time.sleep(0.02)

            else:
                # Benign HTTP/DNS traffic
                evt = SecurityEvent(
                    src_ip="192.168.1.120",
                    dst_ip="8.8.8.8",
                    src_port=53123,
                    dst_port=53,
                    protocol="UDP",
                    packet_size=68,
                    flags=None,
                    flags_list=None,
                    timestamp=now_str,
                    timestamp_epoch=time.time(),
                    summary="UDP 192.168.1.120:53123 -> 8.8.8.8:53"
                )
                ids_engine.process_event(evt)

            time.sleep(random.uniform(1.5, 3.5))

    except KeyboardInterrupt:
        print("\nStopping IDS simulation.")


def shutdown_and_export():
    """Generates a summary report and exports results to JSON on shutdown."""
    print("\n" + "=" * 80)
    print("Exporting Intrusion Detection Session Report to JSON...")
    report_file = ids_engine.export_report()
    stats = ids_engine.get_stats()
    print(f"Report exported successfully to: {report_file}")
    print(f"Packets Processed: {stats.get('packets_processed', 0)}")
    print(f"Total Alerts Detected: {stats.get('total_alerts_session', 0)}")
    print(f"Alerts by Severity: {stats.get('by_severity')}")
    print(f"Alerts by Attack Type: {stats.get('by_attack_type')}")
    print("=" * 80)


def main():
    print("=" * 80)
    print(" modular Intrusion Detection System (IDS) Starting...")
    print("Active Detectors: Port Scan, SYN Flood, Rate Anomaly, Brute Force, Suspicious Traffic")
    print("Alert Persistence: alerts.jsonl & In-Memory Real-Time Buffer")
    print("=" * 80)

    try:
        if sniff is not None:
            try:
                print("Listening for live network traffic (filter: 'ip')... (Press Ctrl+C to stop)")
                sniff(filter="ip", prn=process_packet, store=False)
            except Exception as e:
                print(f"Live sniffing unavailable ({e}). Switching to mock traffic simulation mode.")
                start_mock_traffic()
        else:
            start_mock_traffic()
    except KeyboardInterrupt:
        print("\nCapture session interrupted by user.")
    finally:
        shutdown_and_export()


if __name__ == "__main__":
    main()
