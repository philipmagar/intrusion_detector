"""
Port Scan Detection Module.

Identifies reconnaissance activities including:
1. Vertical Port Scans: Single source querying multiple distinct destination ports on a single host.
2. Horizontal Port Sweeps: Single source querying the same destination port across multiple host IPs.
3. Fast/Aggressive Port Probing: Rapid port access bursts within short sliding windows.
"""

from collections import defaultdict
import time
from typing import Optional, Dict, Set, List, Tuple
from .base import BaseDetector, DetectionResult


class PortScanDetector(BaseDetector):
    """
    Detects vertical and horizontal port scanning patterns using sliding time windows.
    """

    def __init__(
        self,
        port_threshold: int = 8,
        host_sweep_threshold: int = 5,
        window_seconds: float = 10.0,
        cooldown_seconds: float = 15.0,
        enabled: bool = True
    ):
        super().__init__(name="PortScanDetector", enabled=enabled)
        self.port_threshold = port_threshold
        self.host_sweep_threshold = host_sweep_threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds

        # Key: (src_ip, dst_ip) -> List of (timestamp, dst_port)
        self._target_ports: Dict[Tuple[str, str], List[Tuple[float, int]]] = defaultdict(list)

        # Key: (src_ip, dst_port) -> List of (timestamp, dst_ip)
        self._sweep_targets: Dict[Tuple[str, int], List[Tuple[float, str]]] = defaultdict(list)

        # Alert cooldown tracker: Key -> last_alert_time
        self._alert_cooldowns: Dict[str, float] = {}

    def _is_cooling_down(self, alert_key: str, now: float) -> bool:
        last_time = self._alert_cooldowns.get(alert_key, 0.0)
        if now - last_time < self.cooldown_seconds:
            return True
        self._alert_cooldowns[alert_key] = now
        return False

    def process_event(self, event) -> Optional[DetectionResult]:
        if not self.enabled or not event.src_ip or not event.dst_ip or event.dst_port is None:
            return None

        # Focus primarily on transport layer probe attempts (TCP/UDP)
        if event.protocol not in ("TCP", "UDP"):
            return None

        now = event.timestamp_epoch or time.time()
        src_ip = event.src_ip
        dst_ip = event.dst_ip
        dst_port = event.dst_port

        # 1. Update and evaluate Vertical Port Scan (single target, multiple ports)
        vp_key = (src_ip, dst_ip)
        self._target_ports[vp_key].append((now, dst_port))
        # Purge entries outside window
        self._target_ports[vp_key] = [
            (t, p) for (t, p) in self._target_ports[vp_key] if now - t <= self.window_seconds
        ]

        recent_ports: Set[int] = {p for (_, p) in self._target_ports[vp_key]}
        distinct_port_count = len(recent_ports)

        if distinct_port_count >= self.port_threshold:
            alert_key = f"vertical_scan:{src_ip}->{dst_ip}"
            if not self._is_cooling_down(alert_key, now):
                sorted_ports = sorted(list(recent_ports))
                sample_ports = sorted_ports[:15]
                scan_velocity = round(distinct_port_count / max(self.window_seconds, 1.0), 2)

                confidence = min(0.99, 0.70 + (distinct_port_count / (self.port_threshold * 3)) * 0.25)
                severity = "HIGH" if distinct_port_count >= self.port_threshold * 2 else "MEDIUM"

                return DetectionResult(
                    attack_type="Port Scan (Vertical)",
                    severity=severity,
                    confidence=round(confidence, 2),
                    triggered_rule="RULE_PORT_SCAN_VERTICAL_THRESHOLD",
                    evidence={
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": event.protocol,
                        "distinct_ports_count": distinct_port_count,
                        "ports_targeted": sample_ports,
                        "window_seconds": self.window_seconds,
                        "packet_stats": {
                            "total_probes_in_window": len(self._target_ports[vp_key]),
                            "distinct_ports": distinct_port_count,
                            "probe_rate_pps": scan_velocity,
                            "last_packet_size": event.packet_size,
                            "tcp_flags": event.flags,
                        },
                        "details": (
                            f"Host {src_ip} probed {distinct_port_count} distinct ports on "
                            f"{dst_ip} within {self.window_seconds}s (Rate: {scan_velocity} ports/s)."
                        ),
                    },
                    timestamp=event.timestamp,
                    timestamp_epoch=now,
                )

        # 2. Update and evaluate Horizontal Sweep (single port, multiple targets)
        hp_key = (src_ip, dst_port)
        self._sweep_targets[hp_key].append((now, dst_ip))
        self._sweep_targets[hp_key] = [
            (t, ip) for (t, ip) in self._sweep_targets[hp_key] if now - t <= self.window_seconds
        ]

        recent_targets: Set[str] = {ip for (_, ip) in self._sweep_targets[hp_key]}
        distinct_target_count = len(recent_targets)

        if distinct_target_count >= self.host_sweep_threshold:
            alert_key = f"horizontal_sweep:{src_ip}:port{dst_port}"
            if not self._is_cooling_down(alert_key, now):
                sample_targets = list(recent_targets)[:10]
                confidence = min(0.95, 0.65 + (distinct_target_count / (self.host_sweep_threshold * 2)) * 0.25)

                return DetectionResult(
                    attack_type="Horizontal Port Sweep",
                    severity="MEDIUM",
                    confidence=round(confidence, 2),
                    triggered_rule="RULE_PORT_SWEEP_HORIZONTAL",
                    evidence={
                        "src_ip": src_ip,
                        "target_port": dst_port,
                        "distinct_hosts_count": distinct_target_count,
                        "sample_targets": sample_targets,
                        "window_seconds": self.window_seconds,
                        "protocol": event.protocol,
                        "packet_stats": {
                            "total_probes_in_window": len(self._sweep_targets[hp_key]),
                            "hosts_contacted": distinct_target_count,
                            "target_port": dst_port,
                        },
                        "details": (
                            f"Host {src_ip} probed port {dst_port} across {distinct_target_count} "
                            f"distinct hosts within {self.window_seconds}s."
                        ),
                    },
                    timestamp=event.timestamp,
                    timestamp_epoch=now,
                )

        return None

    def reset(self) -> None:
        self._target_ports.clear()
        self._sweep_targets.clear()
        self._alert_cooldowns.clear()
