"""
Suspicious Traffic & Malicious Anomaly Detection Module.

Identifies illegal packet configurations and evasion tactics:
1. TCP Flag Anomalies:
   - NULL Scan: No flags set (flags == "")
   - XMAS Scan: FIN, PSH, and URG flags set simultaneously
   - SYN+FIN Scan: Both SYN and FIN flags set (invalid state transition)
   - FIN-only Scan: Standalone FIN packet without an established session
2. Suspicious / Malware C2 Backdoor Ports:
   - Metasploit/Meterpreter default (4444)
   - Back Orifice (31337)
   - DarkComet / NetBus (12345)
   - Common Botnet IRC (6667)
   - Android ADB remote debug exposure (5555)
3. Protocol & Packet Size Anomalies:
   - Abnormally large DNS packets (> 512 bytes over UDP) indicating possible amplification or exfiltration.
"""

from typing import Optional, Dict, List, Set
import time
from .base import BaseDetector, DetectionResult

SUSPICIOUS_PORTS: Dict[int, str] = {
    4444: "Metasploit / Meterpreter Default C2",
    5555: "Exposed Android Debug Bridge (ADB)",
    6667: "IRC Default (Common Botnet C2)",
    12345: "NetBus / Legacy Trojan Port",
    31337: "Back Orifice / Cult of the Dead Cow",
}


class SuspiciousTrafficDetector(BaseDetector):
    """
    Detects evasion techniques, invalid TCP flag combinations, and malicious port activities.
    """

    def __init__(self, cooldown_seconds: float = 10.0, enabled: bool = True):
        super().__init__(name="SuspiciousTrafficDetector", enabled=enabled)
        self.cooldown_seconds = cooldown_seconds
        self._alert_cooldowns: Dict[str, float] = {}

    def _is_cooling_down(self, alert_key: str, now: float) -> bool:
        last_time = self._alert_cooldowns.get(alert_key, 0.0)
        if now - last_time < self.cooldown_seconds:
            return True
        self._alert_cooldowns[alert_key] = now
        return False

    def process_event(self, event) -> Optional[DetectionResult]:
        if not self.enabled or not event.src_ip:
            return None

        now = event.timestamp_epoch or time.time()
        src_ip = event.src_ip
        dst_ip = event.dst_ip or "UNKNOWN"
        protocol = event.protocol
        flags_list: List[str] = event.flags_list or []
        flags_set: Set[str] = set(flags_list)
        dst_port = event.dst_port
        src_port = event.src_port

        # 1. TCP Flag Anomalies
        if protocol == "TCP":
            # 1a. XMAS Scan (FIN + PSH + URG)
            if {"FIN", "PSH", "URG"}.issubset(flags_set):
                alert_key = f"xmas_scan:{src_ip}->{dst_ip}"
                if not self._is_cooling_down(alert_key, now):
                    return DetectionResult(
                        attack_type="Suspicious TCP Flags (Xmas Scan)",
                        severity="HIGH",
                        confidence=0.98,
                        triggered_rule="RULE_TCP_XMAS_FLAGS",
                        evidence={
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "protocol": "TCP",
                            "flags": event.flags,
                            "packet_stats": {
                                "flags_detected": list(flags_set),
                                "packet_size": event.packet_size,
                            },
                            "details": f"TCP Xmas Scan packet (FIN+PSH+URG) detected from {src_ip} targeting {dst_ip}:{dst_port}.",
                        },
                        timestamp=event.timestamp,
                        timestamp_epoch=now,
                    )

            # 1b. NULL Scan (No flags set)
            if event.flags in ("", "0", "0x00", None) and (not flags_list):
                alert_key = f"null_scan:{src_ip}->{dst_ip}"
                if not self._is_cooling_down(alert_key, now):
                    return DetectionResult(
                        attack_type="Suspicious TCP Flags (Null Scan)",
                        severity="HIGH",
                        confidence=0.95,
                        triggered_rule="RULE_TCP_NULL_FLAGS",
                        evidence={
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "protocol": "TCP",
                            "flags": "NULL (none)",
                            "packet_stats": {
                                "flags_detected": [],
                                "packet_size": event.packet_size,
                            },
                            "details": f"TCP Null Scan packet (no TCP flags set) detected from {src_ip} targeting {dst_ip}:{dst_port}.",
                        },
                        timestamp=event.timestamp,
                        timestamp_epoch=now,
                    )

            # 1c. SYN + FIN Illegal Flag Combination
            if "SYN" in flags_set and "FIN" in flags_set:
                alert_key = f"syn_fin_scan:{src_ip}->{dst_ip}"
                if not self._is_cooling_down(alert_key, now):
                    return DetectionResult(
                        attack_type="Suspicious TCP Flags (SYN+FIN Scan)",
                        severity="CRITICAL",
                        confidence=0.99,
                        triggered_rule="RULE_TCP_ILLEGAL_SYN_FIN",
                        evidence={
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "protocol": "TCP",
                            "flags": event.flags,
                            "packet_stats": {
                                "flags_detected": list(flags_set),
                                "packet_size": event.packet_size,
                            },
                            "details": f"Illegal TCP SYN+FIN combination detected from {src_ip} targeting {dst_ip}:{dst_port}.",
                        },
                        timestamp=event.timestamp,
                        timestamp_epoch=now,
                    )

            # 1d. FIN-Only Scan
            if flags_set == {"FIN"}:
                alert_key = f"fin_scan:{src_ip}->{dst_ip}"
                if not self._is_cooling_down(alert_key, now):
                    return DetectionResult(
                        attack_type="Suspicious TCP Flags (FIN Scan)",
                        severity="MEDIUM",
                        confidence=0.85,
                        triggered_rule="RULE_TCP_FIN_SCAN",
                        evidence={
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "protocol": "TCP",
                            "flags": "FIN",
                            "packet_stats": {
                                "flags_detected": ["FIN"],
                                "packet_size": event.packet_size,
                            },
                            "details": f"Stealth FIN Scan packet detected from {src_ip} targeting {dst_ip}:{dst_port}.",
                        },
                        timestamp=event.timestamp,
                        timestamp_epoch=now,
                    )

        # 2. Suspicious / Malware C2 Port Activity
        for port in (dst_port, src_port):
            if port and port in SUSPICIOUS_PORTS:
                c2_desc = SUSPICIOUS_PORTS[port]
                alert_key = f"suspicious_port:{src_ip}->{dst_ip}:{port}"
                if not self._is_cooling_down(alert_key, now):
                    return DetectionResult(
                        attack_type=f"Suspicious Port Traffic ({c2_desc})",
                        severity="HIGH",
                        confidence=0.88,
                        triggered_rule="RULE_MALWARE_KNOWN_C2_PORT",
                        evidence={
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "protocol": protocol,
                            "flagged_port": port,
                            "c2_description": c2_desc,
                            "packet_stats": {
                                "packet_size": event.packet_size,
                                "flags": event.flags,
                            },
                            "details": f"Traffic associated with known malicious / C2 port {port} ({c2_desc}) between {src_ip} and {dst_ip}.",
                        },
                        timestamp=event.timestamp,
                        timestamp_epoch=now,
                    )

        # 3. DNS Tunneling / Oversized DNS UDP packet anomaly
        if protocol == "UDP" and (dst_port == 53 or src_port == 53) and event.packet_size > 512:
            alert_key = f"dns_anomaly:{src_ip}->{dst_ip}"
            if not self._is_cooling_down(alert_key, now):
                return DetectionResult(
                    attack_type="Suspicious DNS Packet Size",
                    severity="LOW",
                    confidence=0.70,
                    triggered_rule="RULE_DNS_OVERSIZED_UDP_PAYLOAD",
                    evidence={
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": "UDP",
                        "packet_stats": {
                            "packet_size": event.packet_size,
                            "standard_dns_udp_limit": 512,
                        },
                        "details": f"Oversized UDP DNS packet ({event.packet_size} bytes > 512 bytes limit) detected between {src_ip} and {dst_ip}.",
                    },
                    timestamp=event.timestamp,
                    timestamp_epoch=now,
                )

        return None

    def reset(self) -> None:
        self._alert_cooldowns.clear()
