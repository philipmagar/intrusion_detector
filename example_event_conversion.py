"""
Example demonstration showing:
1. Scapy packet conversion into standardized security events.
2. Feeding security events through modular detectors (Port Scan, SYN Flood, Brute Force, Rate Anomaly, Suspicious Traffic).
3. Viewing standardized DetectionResult schema (attack_type, severity, confidence, triggered_rule, evidence, packet_stats).
4. Persisting alerts to local JSON/JSONL and exporting a final JSON session report.
"""

from scapy.layers.inet import IP, TCP, UDP, ICMP
from packet_parser import packet_to_security_event, SecurityEvent
from detectors.base import DetectionResult
from engine import IntrusionDetectorEngine
from alert_manager import AlertManager
import tempfile
import os
import json


def demonstrate():
    print("=" * 80)
    print("1. Standardizing Raw Scapy Packets into SecurityEvents")
    print("=" * 80)

    sample_scapy_packets = [
        ("TCP SYN Probe (Port Scan)", IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=51234, dport=80, flags="S")),
        ("TCP Xmas Scan (Evasion)", IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=51235, dport=22, flags="FPU")),
        ("TCP Null Scan (Evasion)", IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=51236, dport=443, flags=0)),
        ("UDP DNS Query", IP(src="10.0.0.15", dst="8.8.8.8") / UDP(sport=53530, dport=53)),
        ("ICMP Echo Request (Ping)", IP(src="172.16.0.5", dst="172.16.0.1") / ICMP(type=8, code=0)),
    ]

    for desc, pkt in sample_scapy_packets:
        event = packet_to_security_event(pkt)
        print(f"\n[Packet]: {desc}")
        print(f" -> {event.protocol} {event.src_ip}:{event.src_port} -> {event.dst_ip}:{event.dst_port} | Flags: {event.flags} | Size: {event.packet_size}B")

    print("\n" + "=" * 80)
    print("2. Running Modular IDS Engine against Multi-Vector Attack Scenarios")
    print("=" * 80)

    # Setup temporary alert manager for clean demonstration
    temp_dir = tempfile.mkdtemp()
    demo_log_path = os.path.join(temp_dir, "demo_alerts.jsonl")
    alert_mgr = AlertManager(log_file=demo_log_path)
    engine = IntrusionDetectorEngine(alert_manager=alert_mgr)

    # Scenario A: Vertical Port Scan
    print("\n[Simulating Vertical Port Scan...]")
    for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 8080]:
        evt = packet_to_security_event(
            IP(src="192.168.1.205", dst="10.0.0.5") / TCP(sport=50000 + port, dport=port, flags="S")
        )
        engine.process_event(evt)

    # Scenario B: SSH Brute Force
    print("[Simulating SSH Brute Force...]")
    for _ in range(14):
        evt = packet_to_security_event(
            IP(src="192.168.1.210", dst="10.0.0.5") / TCP(sport=54321, dport=22, flags="PA")
        )
        engine.process_event(evt)

    # Scenario C: TCP Xmas Scan Anomaly
    print("[Simulating Xmas Scan Anomaly...]")
    evt = packet_to_security_event(
        IP(src="192.168.1.220", dst="10.0.0.5") / TCP(sport=54322, dport=80, flags="FPU")
    )
    engine.process_event(evt)

    # Scenario D: SYN Flood
    print("[Simulating SYN Flood (30 SYN packets)...]")
    for _ in range(30):
        evt = packet_to_security_event(
            IP(src="192.168.1.230", dst="10.0.0.5") / TCP(sport=54323, dport=80, flags="S")
        )
        engine.process_event(evt)

    # Retrieve and display detected alerts
    recent_alerts = alert_mgr.get_recent_alerts(limit=10)
    print("\n" + "=" * 80)
    print(f"3. Detected Intrusion Alerts ({len(recent_alerts)} incidents in memory)")
    print("=" * 80)

    for alert in recent_alerts:
        print(f"\n[ALERT: {alert['attack_type']}]")
        print(f"  Severity:       {alert['severity']}")
        print(f"  Confidence:     {int(alert['confidence'] * 100)}%")
        print(f"  Triggered Rule: {alert['triggered_rule']}")
        print(f"  Source -> Dest: {alert['src_ip']}:{alert['src_port']} -> {alert['dst_ip']}:{alert['dst_port']}")
        print(f"  Evidence Stats: {alert['packet_stats']}")
        print(f"  Details:        {alert['evidence'].get('details')}")

    # Export report
    demo_report_path = os.path.join(temp_dir, "demo_scan_report.json")
    exported_file = engine.export_report(filepath=demo_report_path)
    print("\n" + "=" * 80)
    print(f"4. Session Report Exported to JSON: {exported_file}")
    print("=" * 80)

    with open(exported_file, "r") as f:
        report_data = json.load(f)

    print("Export Summary Statistics:")
    print(json.dumps(report_data["summary_statistics"], indent=2))


if __name__ == "__main__":
    demonstrate()
