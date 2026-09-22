"""
SYN Flood Detection Module.

Identifies TCP SYN Flood Denial-of-Service attacks by monitoring:
1. High volume / rate of TCP SYN packets directed at target IPs.
2. Low SYN-to-ACK completion ratios (half-open connection buildup).
3. Concentrated or distributed SYN packet storms.
"""

from collections import defaultdict
import time
from typing import Optional, Dict, List, Tuple
from .base import BaseDetector, DetectionResult


class SynFloodDetector(BaseDetector):
    """
    Detects SYN Flood DOS/DDOS patterns by tracking TCP SYN vs ACK frequencies.
    """

    def __init__(
        self,
        syn_threshold: int = 25,
        window_seconds: float = 5.0,
        syn_ack_ratio_threshold: float = 4.0,
        cooldown_seconds: float = 10.0,
        enabled: bool = True
    ):
        super().__init__(name="SynFloodDetector", enabled=enabled)
        self.syn_threshold = syn_threshold
        self.window_seconds = window_seconds
        self.syn_ack_ratio_threshold = syn_ack_ratio_threshold
        self.cooldown_seconds = cooldown_seconds

        # Key: dst_ip -> List of (timestamp_epoch, is_syn: bool, is_ack: bool, src_ip, dst_port)
        self._target_traffic: Dict[str, List[Tuple[float, bool, bool, str, Optional[int]]]] = defaultdict(list)

        # Key: src_ip -> List of (timestamp_epoch, dst_ip, dst_port)
        self._source_syns: Dict[str, List[Tuple[float, str, Optional[int]]]] = defaultdict(list)

        # Cooldown tracker
        self._alert_cooldowns: Dict[str, float] = {}

    def _is_cooling_down(self, alert_key: str, now: float) -> bool:
        last_time = self._alert_cooldowns.get(alert_key, 0.0)
        if now - last_time < self.cooldown_seconds:
            return True
        self._alert_cooldowns[alert_key] = now
        return False

    def process_event(self, event) -> Optional[DetectionResult]:
        if not self.enabled or event.protocol != "TCP" or not event.dst_ip:
            return None

        flags_list = event.flags_list or []
        is_syn = "SYN" in flags_list and "ACK" not in flags_list
        is_ack = "ACK" in flags_list

        if not is_syn and not is_ack:
            return None

        now = event.timestamp_epoch or time.time()
        dst_ip = event.dst_ip
        src_ip = event.src_ip or "UNKNOWN"
        dst_port = event.dst_port

        # Track traffic per target
        self._target_traffic[dst_ip].append((now, is_syn, is_ack, src_ip, dst_port))
        self._target_traffic[dst_ip] = [
            record for record in self._target_traffic[dst_ip] if now - record[0] <= self.window_seconds
        ]

        # Track single source SYN bursts
        if is_syn and src_ip != "UNKNOWN":
            self._source_syns[src_ip].append((now, dst_ip, dst_port))
            self._source_syns[src_ip] = [
                record for record in self._source_syns[src_ip] if now - record[0] <= self.window_seconds
            ]

        # 1. Check target-level SYN Flood
        target_records = self._target_traffic[dst_ip]
        syn_count = sum(1 for _, syn, _, _, _ in target_records if syn)
        ack_count = sum(1 for _, _, ack, _, _ in target_records if ack)

        ratio = (syn_count / max(ack_count, 1)) if syn_count > 0 else 0.0
        rate_pps = round(syn_count / max(self.window_seconds, 1.0), 1)

        if syn_count >= self.syn_threshold and (ratio >= self.syn_ack_ratio_threshold or ack_count == 0):
            alert_key = f"syn_flood_target:{dst_ip}"
            if not self._is_cooling_down(alert_key, now):
                unique_attackers = len({s for _, syn, _, s, _ in target_records if syn})
                targeted_ports = list({p for _, syn, _, _, p in target_records if syn and p is not None})[:10]

                severity = "CRITICAL" if syn_count >= self.syn_threshold * 2 else "HIGH"
                confidence = min(0.98, 0.75 + (syn_count / (self.syn_threshold * 4)) * 0.20)

                return DetectionResult(
                    attack_type="SYN Flood (DoS)",
                    severity=severity,
                    confidence=round(confidence, 2),
                    triggered_rule="RULE_SYN_FLOOD_TARGET_THRESHOLD",
                    evidence={
                        "target_ip": dst_ip,
                        "primary_source_ip": src_ip,
                        "unique_sources_count": unique_attackers,
                        "targeted_ports": targeted_ports,
                        "window_seconds": self.window_seconds,
                        "packet_stats": {
                            "syn_count": syn_count,
                            "ack_count": ack_count,
                            "syn_to_ack_ratio": round(ratio, 2),
                            "syn_rate_pps": rate_pps,
                            "last_packet_size": event.packet_size,
                        },
                        "details": (
                            f"Detected SYN flood targeting {dst_ip}: {syn_count} SYN packets "
                            f"(rate: {rate_pps} pps, SYN/ACK ratio: {round(ratio, 1)}) within {self.window_seconds}s."
                        ),
                    },
                    timestamp=event.timestamp,
                    timestamp_epoch=now,
                )

        # 2. Check source-level SYN Storm
        if src_ip != "UNKNOWN":
            src_syn_count = len(self._source_syns[src_ip])
            if src_syn_count >= self.syn_threshold:
                alert_key = f"syn_flood_source:{src_ip}"
                if not self._is_cooling_down(alert_key, now):
                    src_rate = round(src_syn_count / max(self.window_seconds, 1.0), 1)
                    return DetectionResult(
                        attack_type="SYN Flood Source Storm",
                        severity="HIGH",
                        confidence=0.92,
                        triggered_rule="RULE_SYN_FLOOD_SOURCE_BURST",
                        evidence={
                            "src_ip": src_ip,
                            "target_ip": dst_ip,
                            "window_seconds": self.window_seconds,
                            "packet_stats": {
                                "syn_packets_sent": src_syn_count,
                                "syn_rate_pps": src_rate,
                                "target_ip": dst_ip,
                                "target_port": dst_port,
                            },
                            "details": f"Host {src_ip} transmitted {src_syn_count} SYN packets ({src_rate} pps) within {self.window_seconds}s.",
                        },
                        timestamp=event.timestamp,
                        timestamp_epoch=now,
                    )

        return None

    def reset(self) -> None:
        self._target_traffic.clear()
        self._source_syns.clear()
        self._alert_cooldowns.clear()
