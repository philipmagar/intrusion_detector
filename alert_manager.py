"""
Alert Manager and Persistent JSON Storage.

Handles:
1. Thread-safe in-memory alert ring buffer for real-time dashboard display.
2. Local JSON/JSONL logging (`alerts.jsonl`) storing full evidence, severity, confidence, and packet stats.
3. Structured JSON report export (`export_json_report()`) at the conclusion of a capture session.
"""

from collections import deque, Counter
from dataclasses import asdict
from datetime import datetime
import json
import os
import threading
from typing import Dict, Any, List, Optional

from detectors.base import DetectionResult
from packet_parser import SecurityEvent


class AlertManager:
    """
    Coordinates alert persistence to local JSON files and maintains an in-memory
    cache for real-time dashboard consumption.
    """

    def __init__(
        self,
        log_file: Optional[str] = None,
        max_memory_alerts: int = 1000
    ):
        if log_file is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.log_file = os.path.join(base_dir, "alerts.jsonl")
        else:
            self.log_file = log_file

        self.max_memory_alerts = max_memory_alerts
        self._memory_alerts: deque = deque(maxlen=max_memory_alerts)
        self._lock = threading.Lock()
        self._total_alerts_count = 0
        self._start_time = datetime.now()

    def record_alert(
        self,
        result: DetectionResult,
        event: Optional[SecurityEvent] = None
    ) -> Dict[str, Any]:
        """
        Records a detection result into the in-memory buffer and appends it to alerts.jsonl.
        
        Maintains backwards compatibility with dashboard fields (ip, type, time)
        while appending rich IDS metadata (severity, confidence, triggered_rule, evidence).
        """
        primary_ip = (
            result.evidence.get("src_ip")
            or (event.src_ip if event else None)
            or result.evidence.get("primary_source_ip")
            or result.evidence.get("target_ip")
            or "UNKNOWN"
        )
        dst_ip = (
            result.evidence.get("dst_ip")
            or (event.dst_ip if event else None)
            or result.evidence.get("target_ip")
        )

        alert_dict: Dict[str, Any] = {
            # Legacy & Dashboard Compatibility Fields
            "ip": primary_ip,
            "type": result.attack_type,
            "time": result.timestamp,
            # Enhanced Standardized Security Alert Fields
            "attack_type": result.attack_type,
            "severity": result.severity,
            "confidence": result.confidence,
            "triggered_rule": result.triggered_rule,
            "src_ip": primary_ip,
            "dst_ip": dst_ip,
            "src_port": result.evidence.get("src_port") or (event.src_port if event else None),
            "dst_port": result.evidence.get("dst_port") or (event.dst_port if event else None),
            "protocol": result.evidence.get("protocol") or (event.protocol if event else "IP"),
            "packet_size": event.packet_size if event else result.evidence.get("packet_stats", {}).get("last_packet_size", 0),
            "flags": event.flags if event else None,
            "flags_list": event.flags_list if event else [],
            "timestamp_epoch": result.timestamp_epoch,
            # Rich evidence and statistics
            "evidence": result.evidence,
            "packet_stats": result.evidence.get("packet_stats", {}),
        }

        # 1. Update In-Memory Ring Buffer
        with self._lock:
            self._memory_alerts.append(alert_dict)
            self._total_alerts_count += 1

        # 2. Append to Local JSONL File
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert_dict) + "\n")
        except Exception as e:
            print(f"[AlertManager ERROR] Failed to write to {self.log_file}: {e}")

        return alert_dict

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve the most recent N alerts from in-memory cache (newest first)."""
        with self._lock:
            alerts = list(self._memory_alerts)
        return list(reversed(alerts))[:limit]

    def get_all_memory_alerts(self) -> List[Dict[str, Any]]:
        """Retrieve all currently cached alerts."""
        with self._lock:
            return list(self._memory_alerts)

    def get_stats(self) -> Dict[str, Any]:
        """Compute aggregated statistics over currently stored alerts."""
        with self._lock:
            alerts = list(self._memory_alerts)

        severity_counts = Counter(a.get("severity", "UNKNOWN") for a in alerts)
        attack_type_counts = Counter(a.get("attack_type", a.get("type", "UNKNOWN")) for a in alerts)
        top_ips = Counter(a.get("ip", "UNKNOWN") for a in alerts).most_common(5)

        return {
            "total_alerts_session": len(alerts),
            "total_alerts_all_time": self._total_alerts_count,
            "by_severity": dict(severity_counts),
            "by_attack_type": dict(attack_type_counts),
            "top_source_ips": dict(top_ips),
            "uptime_seconds": (datetime.now() - self._start_time).total_seconds(),
        }

    def export_json_report(
        self,
        output_filepath: Optional[str] = None,
        session_metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Exports a complete structured JSON report of all detected incidents and statistics.
        
        Args:
            output_filepath: Target path for the report file. Defaults to `scan_report_<timestamp>.json`.
            session_metadata: Optional metadata (e.g. packet counts, duration, interface).
            
        Returns:
            str: Path to the generated JSON report.
        """
        if output_filepath is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            ts_suffix = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filepath = os.path.join(base_dir, f"scan_report_{ts_suffix}.json")

        with self._lock:
            alerts = list(self._memory_alerts)

        report_data = {
            "report_metadata": {
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "session_start": self._start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_alerts_detected": len(alerts),
                **(session_metadata or {})
            },
            "summary_statistics": self.get_stats(),
            "alerts": alerts,
        }

        with open(output_filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        return output_filepath

    def clear(self) -> None:
        """Clear memory cache."""
        with self._lock:
            self._memory_alerts.clear()
            self._total_alerts_count = 0


# Global singleton instance for easy import across modules
global_alert_manager = AlertManager()
