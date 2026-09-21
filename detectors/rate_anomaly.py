"""
Abnormal Connection Rate and Traffic Anomaly Detection Module.

Identifies traffic volume anomalies including:
1. High Packet-Per-Second (PPS) bursts from single hosts.
2. ICMP Echo Floods (Ping Floods / Smurf attacks).
3. UDP Storms / Amplification traffic bursts.
4. Total connection/bandwidth volume spikes exceeding sliding window baselines.
"""

from collections import defaultdict
import time
from typing import Optional, Dict, List, Tuple
from .base import BaseDetector, DetectionResult


class RateAnomalyDetector(BaseDetector):
    """
    Detects abnormal traffic volume and packet rate anomalies.
    """

    def __init__(
        self,
        pps_threshold: float = 30.0,
        icmp_threshold: int = 20,
        udp_threshold: int = 35,
        window_seconds: float = 5.0,
        cooldown_seconds: float = 10.0,
        enabled: bool = True
    ):
        super().__init__(name="RateAnomalyDetector", enabled=enabled)
        self.pps_threshold = pps_threshold
        self.icmp_threshold = icmp_threshold
        self.udp_threshold = udp_threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds

        # Key: src_ip -> List of (timestamp_epoch, packet_size, protocol, dst_ip, dst_port)
        self._host_packets: Dict[str, List[Tuple[float, int, str, Optional[str], Optional[int]]]] = defaultdict(list)

        # Alert cooldown tracker
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
        dst_ip = event.dst_ip
        protocol = event.protocol
        size = event.packet_size or 0
        dst_port = event.dst_port

        # Update host history
        self._host_packets[src_ip].append((now, size, protocol, dst_ip, dst_port))
        self._host_packets[src_ip] = [
            pkt for pkt in self._host_packets[src_ip] if now - pkt[0] <= self.window_seconds
        ]

        recent_packets = self._host_packets[src_ip]
        total_count = len(recent_packets)
        total_bytes = sum(pkt[1] for pkt in recent_packets)
        rate_pps = round(total_count / max(self.window_seconds, 1.0), 1)

        # 1. Check ICMP Flood
        if protocol in ("ICMP", "ICMPv6"):
            icmp_count = sum(1 for pkt in recent_packets if pkt[2] in ("ICMP", "ICMPv6"))
            if icmp_count >= self.icmp_threshold:
                alert_key = f"icmp_flood:{src_ip}"
                if not self._is_cooling_down(alert_key, now):
                    return DetectionResult(
                        attack_type="ICMP Flood (Ping Flood)",
                        severity="HIGH",
                        confidence=0.90,
                        triggered_rule="RULE_ICMP_FLOOD_THRESHOLD",
                        evidence={
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "protocol": protocol,
                            "window_seconds": self.window_seconds,
                            "packet_stats": {
                                "icmp_packet_count": icmp_count,
                                "icmp_rate_pps": round(icmp_count / max(self.window_seconds, 1.0), 1),
                                "total_bytes": total_bytes,
                            },
                            "details": (
                                f"Host {src_ip} generated {icmp_count} ICMP packets within "
                                f"{self.window_seconds}s (Rate: {round(icmp_count / max(self.window_seconds, 1.0), 1)} pps)."
                            ),
                        },
                        timestamp=event.timestamp,
                        timestamp_epoch=now,
                    )

        # 2. Check UDP Flood
        if protocol == "UDP":
            udp_count = sum(1 for pkt in recent_packets if pkt[2] == "UDP")
            if udp_count >= self.udp_threshold:
                alert_key = f"udp_flood:{src_ip}"
                if not self._is_cooling_down(alert_key, now):
                    return DetectionResult(
                        attack_type="UDP Flood (Traffic Storm)",
                        severity="HIGH",
                        confidence=0.88,
                        triggered_rule="RULE_UDP_FLOOD_THRESHOLD",
                        evidence={
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "protocol": "UDP",
                            "window_seconds": self.window_seconds,
                            "packet_stats": {
                                "udp_packet_count": udp_count,
                                "udp_rate_pps": round(udp_count / max(self.window_seconds, 1.0), 1),
                                "total_bytes": total_bytes,
                            },
                            "details": (
                                f"Host {src_ip} flooded {udp_count} UDP packets within {self.window_seconds}s "
                                f"(Rate: {round(udp_count / max(self.window_seconds, 1.0), 1)} pps)."
                            ),
                        },
                        timestamp=event.timestamp,
                        timestamp_epoch=now,
                    )

        # 3. Check General High PPS / Abnormal Connection Rate
        if rate_pps >= self.pps_threshold:
            alert_key = f"rate_anomaly:{src_ip}"
            if not self._is_cooling_down(alert_key, now):
                severity = "CRITICAL" if rate_pps >= self.pps_threshold * 2 else "MEDIUM"
                confidence = min(0.95, 0.70 + (rate_pps / (self.pps_threshold * 3)) * 0.25)

                return DetectionResult(
                    attack_type="Abnormal Connection Rate",
                    severity=severity,
                    confidence=round(confidence, 2),
                    triggered_rule="RULE_TRAFFIC_BURST_PPS_THRESHOLD",
                    evidence={
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": protocol,
                        "window_seconds": self.window_seconds,
                        "packet_stats": {
                            "packet_count_in_window": total_count,
                            "packet_rate_pps": rate_pps,
                            "total_bytes_transferred": total_bytes,
                            "last_packet_size": size,
                        },
                        "details": (
                            f"Host {src_ip} exceeded normal connection rate with {total_count} packets "
                            f"({rate_pps} pps, {total_bytes} bytes) in {self.window_seconds}s."
                        ),
                    },
                    timestamp=event.timestamp,
                    timestamp_epoch=now,
                )

        return None

    def reset(self) -> None:
        self._host_packets.clear()
        self._alert_cooldowns.clear()
