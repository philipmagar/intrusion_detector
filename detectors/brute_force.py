"""
Brute-Force Pattern Detection Module.

Identifies repeated, automated authentication attempts and connection bursts
directed at common administrative, remote access, and credential services:
- SSH (port 22)
- Telnet (port 23)
- FTP (port 21)
- RDP (port 3389)
- SMB (port 445)
- Databases (MySQL 3306, PostgreSQL 5432, MSSQL 1433, Redis 6379)
- Web Management Interfaces (8080, 8443, 80, 443)
"""

from collections import defaultdict
import time
from typing import Optional, Dict, List, Tuple
from .base import BaseDetector, DetectionResult

# Common authentication and remote management ports mapped to service names
AUTH_SERVICES: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP Auth",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS Auth",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt / Management",
    8443: "HTTPS-Alt / Management",
}


class BruteForceDetector(BaseDetector):
    """
    Detects brute-force login attempts against authentication services.
    """

    def __init__(
        self,
        attempt_threshold: int = 12,
        window_seconds: float = 20.0,
        cooldown_seconds: float = 15.0,
        enabled: bool = True
    ):
        super().__init__(name="BruteForceDetector", enabled=enabled)
        self.attempt_threshold = attempt_threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds

        # Key: (src_ip, dst_ip, dst_port) -> List of (timestamp_epoch, packet_size, flags)
        self._auth_attempts: Dict[Tuple[str, str, int], List[Tuple[float, int, Optional[str]]]] = defaultdict(list)

        # Alert cooldown tracker
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

        dst_port = event.dst_port
        # Check if destination port corresponds to a known auth/management service
        if dst_port not in AUTH_SERVICES:
            return None

        # Look for connection initialization or data transfer (SYN, PSH+ACK, etc.)
        flags_list = event.flags_list or []
        is_syn = "SYN" in flags_list
        is_data = "PSH" in flags_list or event.packet_size > 60

        if not is_syn and not is_data and event.protocol != "TCP":
            return None

        now = event.timestamp_epoch or time.time()
        src_ip = event.src_ip
        dst_ip = event.dst_ip
        service_name = AUTH_SERVICES[dst_port]

        key = (src_ip, dst_ip, dst_port)
        self._auth_attempts[key].append((now, event.packet_size, event.flags))
        self._auth_attempts[key] = [
            att for att in self._auth_attempts[key] if now - att[0] <= self.window_seconds
        ]

        attempt_count = len(self._auth_attempts[key])

        if attempt_count >= self.attempt_threshold:
            alert_key = f"brute_force:{src_ip}->{dst_ip}:{dst_port}"
            if not self._is_cooling_down(alert_key, now):
                attempt_rate = round(attempt_count / max(self.window_seconds, 1.0), 2)
                confidence = min(0.96, 0.75 + (attempt_count / (self.attempt_threshold * 2.5)) * 0.20)
                severity = "HIGH" if attempt_count >= self.attempt_threshold * 2 else "MEDIUM"

                return DetectionResult(
                    attack_type=f"Brute Force ({service_name})",
                    severity=severity,
                    confidence=round(confidence, 2),
                    triggered_rule=f"RULE_AUTH_BURST_{service_name.upper().replace(' ', '_').replace('-', '_')}",
                    evidence={
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "service": service_name,
                        "window_seconds": self.window_seconds,
                        "packet_stats": {
                            "attempt_count": attempt_count,
                            "attempt_rate_per_sec": attempt_rate,
                            "service_port": dst_port,
                            "last_packet_flags": event.flags,
                        },
                        "details": (
                            f"Host {src_ip} performed {attempt_count} rapid connection/auth attempts "
                            f"against {service_name} on {dst_ip}:{dst_port} within {self.window_seconds}s."
                        ),
                    },
                    timestamp=event.timestamp,
                    timestamp_epoch=now,
                )

        return None

    def reset(self) -> None:
        self._auth_attempts.clear()
        self._alert_cooldowns.clear()
