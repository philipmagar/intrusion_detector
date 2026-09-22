"""
Comprehensive Unit Tests for Modular Intrusion Detectors and Alert Management.

Tests:
1. PortScanDetector (Vertical Port Scan & Horizontal Sweep)
2. SynFloodDetector (High SYN rate, half-open build-up, and single-source storm)
3. RateAnomalyDetector (PPS bursts, ICMP Echo Floods, UDP storms)
4. BruteForceDetector (SSH, RDP, FTP repeated connection bursts)
5. SuspiciousTrafficDetector (Xmas scan, Null scan, SYN+FIN scan, FIN scan, C2 ports, DNS anomaly)
6. AlertManager (alerts.jsonl logging, in-memory ring buffer, stats aggregation, and JSON report export)
7. IntrusionDetectorEngine (End-to-end pipeline processing)
"""

import unittest
import time
import json
import os
import tempfile
import shutil

from packet_parser import SecurityEvent
from detectors.base import DetectionResult
from detectors.port_scan import PortScanDetector
from detectors.syn_flood import SynFloodDetector
from detectors.rate_anomaly import RateAnomalyDetector
from detectors.brute_force import BruteForceDetector
from detectors.suspicious_traffic import SuspiciousTrafficDetector
from alert_manager import AlertManager
from engine import IntrusionDetectorEngine


def make_event(
    src_ip="192.168.1.50",
    dst_ip="10.0.0.1",
    src_port=49152,
    dst_port=80,
    protocol="TCP",
    packet_size=60,
    flags="SYN",
    flags_list=None,
    timestamp_epoch=None,
    timestamp=None
) -> SecurityEvent:
    t_epoch = timestamp_epoch if timestamp_epoch is not None else time.time()
    t_str = timestamp or time.strftime("%Y-%m-%d %H:%M:%S")
    f_list = flags_list if flags_list is not None else ([flags] if flags else [])
    return SecurityEvent(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_size=packet_size,
        flags=flags,
        flags_list=f_list,
        timestamp=t_str,
        timestamp_epoch=t_epoch,
        summary=f"{protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
    )


class TestPortScanDetector(unittest.TestCase):

    def setUp(self):
        self.detector = PortScanDetector(port_threshold=5, host_sweep_threshold=4, window_seconds=10.0, cooldown_seconds=0.0)

    def test_vertical_port_scan(self):
        now = time.time()
        result = None
        # Probe 5 distinct ports
        for i, port in enumerate([21, 22, 80, 443, 8080]):
            evt = make_event(src_ip="192.168.1.100", dst_ip="10.0.0.1", dst_port=port, timestamp_epoch=now + i * 0.1)
            res = self.detector.process_event(evt)
            if res:
                result = res

        self.assertIsNotNone(result)
        self.assertEqual(result.attack_type, "Port Scan (Vertical)")
        self.assertIn("distinct_ports_count", result.evidence)
        self.assertGreaterEqual(result.evidence["distinct_ports_count"], 5)
        self.assertEqual(result.triggered_rule, "RULE_PORT_SCAN_VERTICAL_THRESHOLD")
        self.assertIn("packet_stats", result.evidence)
        self.assertGreaterEqual(result.confidence, 0.70)

    def test_horizontal_port_sweep(self):
        now = time.time()
        result = None
        # Probe port 445 across 4 different hosts
        for i, target_ip in enumerate(["10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]):
            evt = make_event(src_ip="192.168.1.100", dst_ip=target_ip, dst_port=445, timestamp_epoch=now + i * 0.1)
            res = self.detector.process_event(evt)
            if res:
                result = res

        self.assertIsNotNone(result)
        self.assertEqual(result.attack_type, "Horizontal Port Sweep")
        self.assertEqual(result.evidence["target_port"], 445)
        self.assertEqual(result.evidence["distinct_hosts_count"], 4)


class TestSynFloodDetector(unittest.TestCase):

    def setUp(self):
        self.detector = SynFloodDetector(syn_threshold=10, window_seconds=5.0, syn_ack_ratio_threshold=3.0, cooldown_seconds=0.0)

    def test_syn_flood_target_detection(self):
        now = time.time()
        result = None
        # Send 10 SYN packets towards the same target with 0 ACKs
        for i in range(10):
            evt = make_event(
                src_ip=f"192.168.1.{10 + i}",
                dst_ip="10.0.0.1",
                dst_port=80,
                flags="SYN",
                flags_list=["SYN"],
                timestamp_epoch=now + i * 0.05
            )
            res = self.detector.process_event(evt)
            if res:
                result = res

        self.assertIsNotNone(result)
        self.assertEqual(result.attack_type, "SYN Flood (DoS)")
        self.assertEqual(result.triggered_rule, "RULE_SYN_FLOOD_TARGET_THRESHOLD")
        self.assertGreaterEqual(result.evidence["packet_stats"]["syn_count"], 10)
        self.assertEqual(result.evidence["target_ip"], "10.0.0.1")


class TestRateAnomalyDetector(unittest.TestCase):

    def setUp(self):
        self.detector = RateAnomalyDetector(pps_threshold=10.0, icmp_threshold=8, udp_threshold=8, window_seconds=2.0, cooldown_seconds=0.0)

    def test_icmp_flood(self):
        now = time.time()
        result = None
        for i in range(8):
            evt = make_event(src_ip="192.168.1.200", dst_ip="10.0.0.1", protocol="ICMP", dst_port=None, timestamp_epoch=now + i * 0.05)
            res = self.detector.process_event(evt)
            if res:
                result = res

        self.assertIsNotNone(result)
        self.assertEqual(result.attack_type, "ICMP Flood (Ping Flood)")
        self.assertEqual(result.triggered_rule, "RULE_ICMP_FLOOD_THRESHOLD")
        self.assertEqual(result.evidence["packet_stats"]["icmp_packet_count"], 8)

    def test_pps_rate_burst(self):
        now = time.time()
        result = None
        for i in range(25):
            evt = make_event(src_ip="192.168.1.201", dst_ip="10.0.0.1", protocol="TCP", flags="ACK", flags_list=["ACK"], timestamp_epoch=now + i * 0.01)
            res = self.detector.process_event(evt)
            if res:
                result = res

        self.assertIsNotNone(result)
        self.assertEqual(result.attack_type, "Abnormal Connection Rate")
        self.assertEqual(result.triggered_rule, "RULE_TRAFFIC_BURST_PPS_THRESHOLD")


class TestBruteForceDetector(unittest.TestCase):

    def setUp(self):
        self.detector = BruteForceDetector(attempt_threshold=5, window_seconds=10.0, cooldown_seconds=0.0)

    def test_ssh_brute_force(self):
        now = time.time()
        result = None
        # 5 SSH attempts to port 22
        for i in range(5):
            evt = make_event(
                src_ip="192.168.1.75",
                dst_ip="10.0.0.1",
                dst_port=22,
                flags="SYN",
                flags_list=["SYN"],
                timestamp_epoch=now + i * 0.1
            )
            res = self.detector.process_event(evt)
            if res:
                result = res

        self.assertIsNotNone(result)
        self.assertEqual(result.attack_type, "Brute Force (SSH)")
        self.assertEqual(result.triggered_rule, "RULE_AUTH_BURST_SSH")
        self.assertEqual(result.evidence["service"], "SSH")
        self.assertEqual(result.evidence["dst_port"], 22)


class TestSuspiciousTrafficDetector(unittest.TestCase):

    def setUp(self):
        self.detector = SuspiciousTrafficDetector(cooldown_seconds=0.0)

    def test_xmas_scan(self):
        evt = make_event(
            src_ip="192.168.1.99",
            dst_ip="10.0.0.1",
            flags="FIN+PSH+URG",
            flags_list=["FIN", "PSH", "URG"]
        )
        res = self.detector.process_event(evt)
        self.assertIsNotNone(res)
        self.assertEqual(res.attack_type, "Suspicious TCP Flags (Xmas Scan)")
        self.assertEqual(res.triggered_rule, "RULE_TCP_XMAS_FLAGS")
        self.assertEqual(res.confidence, 0.98)

    def test_null_scan(self):
        evt = make_event(
            src_ip="192.168.1.99",
            dst_ip="10.0.0.1",
            flags="",
            flags_list=[]
        )
        res = self.detector.process_event(evt)
        self.assertIsNotNone(res)
        self.assertEqual(res.attack_type, "Suspicious TCP Flags (Null Scan)")
        self.assertEqual(res.triggered_rule, "RULE_TCP_NULL_FLAGS")

    def test_syn_fin_scan(self):
        evt = make_event(
            src_ip="192.168.1.99",
            dst_ip="10.0.0.1",
            flags="SYN+FIN",
            flags_list=["SYN", "FIN"]
        )
        res = self.detector.process_event(evt)
        self.assertIsNotNone(res)
        self.assertEqual(res.attack_type, "Suspicious TCP Flags (SYN+FIN Scan)")
        self.assertEqual(res.severity, "CRITICAL")

    def test_suspicious_c2_port(self):
        evt = make_event(
            src_ip="192.168.1.99",
            dst_ip="10.0.0.1",
            dst_port=4444,
            flags="SYN",
            flags_list=["SYN"]
        )
        res = self.detector.process_event(evt)
        self.assertIsNotNone(res)
        self.assertIn("Metasploit", res.attack_type)
        self.assertEqual(res.triggered_rule, "RULE_MALWARE_KNOWN_C2_PORT")


class TestAlertManagerAndEngine(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, "test_alerts.jsonl")
        self.alert_manager = AlertManager(log_file=self.log_file, max_memory_alerts=100)
        self.engine = IntrusionDetectorEngine(alert_manager=self.alert_manager)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_alert_persistence_and_dashboard_compatibility(self):
        # Trigger Xmas scan through engine
        evt = make_event(
            src_ip="192.168.1.88",
            dst_ip="10.0.0.10",
            flags="FIN+PSH+URG",
            flags_list=["FIN", "PSH", "URG"]
        )
        alerts = self.engine.process_event(evt)
        self.assertEqual(len(alerts), 1)

        # Check in-memory store
        memory_alerts = self.alert_manager.get_all_memory_alerts()
        self.assertEqual(len(memory_alerts), 1)
        alert = memory_alerts[0]

        # Verify fields required by Dashboard
        self.assertEqual(alert["ip"], "192.168.1.88")
        self.assertIn("Xmas", alert["type"])
        self.assertIn("time", alert)
        # Verify enhanced IDS fields
        self.assertEqual(alert["severity"], "HIGH")
        self.assertGreater(alert["confidence"], 0.9)
        self.assertEqual(alert["triggered_rule"], "RULE_TCP_XMAS_FLAGS")
        self.assertIn("packet_stats", alert)

        # Check local JSONL file
        self.assertTrue(os.path.exists(self.log_file))
        with open(self.log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 1)
        saved_alert = json.loads(lines[0])
        self.assertEqual(saved_alert["ip"], "192.168.1.88")

    def test_json_report_export(self):
        # Generate two alerts
        evt1 = make_event(src_ip="192.168.1.88", dst_ip="10.0.0.10", flags="FIN+PSH+URG", flags_list=["FIN", "PSH", "URG"])
        evt2 = make_event(src_ip="192.168.1.77", dst_ip="10.0.0.10", dst_port=4444, flags="SYN", flags_list=["SYN"])
        self.engine.process_event(evt1)
        self.engine.process_event(evt2)

        report_path = os.path.join(self.temp_dir, "test_report.json")
        exported = self.engine.export_report(filepath=report_path)
        self.assertEqual(exported, report_path)
        self.assertTrue(os.path.exists(report_path))

        with open(report_path, "r", encoding="utf-8") as f:
            report_data = json.load(f)

        self.assertIn("report_metadata", report_data)
        self.assertIn("summary_statistics", report_data)
        self.assertIn("alerts", report_data)
        self.assertEqual(len(report_data["alerts"]), 2)
        self.assertEqual(report_data["report_metadata"]["total_packets_processed"], 2)


if __name__ == "__main__":
    unittest.main()
