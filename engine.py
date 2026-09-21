"""
Intrusion Detection System Engine.

Coordinates multiple modular detectors (Port Scan, SYN Flood, Rate Anomaly,
Brute Force, Suspicious Traffic), passes standardized SecurityEvent objects through
the detection pipeline, and delegates triggered alerts to the AlertManager.
"""

from typing import List, Optional, Callable, Dict, Any
import time

from detectors.base import BaseDetector, DetectionResult
from detectors.port_scan import PortScanDetector
from detectors.syn_flood import SynFloodDetector
from detectors.rate_anomaly import RateAnomalyDetector
from detectors.brute_force import BruteForceDetector
from detectors.suspicious_traffic import SuspiciousTrafficDetector

from alert_manager import AlertManager, global_alert_manager
from packet_parser import SecurityEvent


class IntrusionDetectorEngine:
    """
    Central IDS Pipeline that orchestrates all detection modules.
    """

    def __init__(
        self,
        alert_manager: Optional[AlertManager] = None,
        detectors: Optional[List[BaseDetector]] = None,
        on_alert_callback: Optional[Callable[[DetectionResult, Dict[str, Any]], None]] = None
    ):
        self.alert_manager = alert_manager or global_alert_manager
        self.on_alert_callback = on_alert_callback

        if detectors is None:
            # Register default built-in detectors
            self.detectors: List[BaseDetector] = [
                PortScanDetector(),
                SynFloodDetector(),
                RateAnomalyDetector(),
                BruteForceDetector(),
                SuspiciousTrafficDetector(),
            ]
        else:
            self.detectors = detectors

        self._packets_processed = 0
        self._start_time = time.time()

    def add_detector(self, detector: BaseDetector) -> None:
        """Register an additional detector into the pipeline."""
        self.detectors.append(detector)

    def process_event(self, event: SecurityEvent) -> List[DetectionResult]:
        """
        Feeds a normalized SecurityEvent through all active detection modules.
        Returns any generated DetectionResults.
        """
        self._packets_processed += 1
        alerts_generated: List[DetectionResult] = []

        for detector in self.detectors:
            if not detector.enabled:
                continue

            try:
                result = detector.process_event(event)
                if result is not None:
                    # Persist alert and update in-memory cache
                    alert_record = self.alert_manager.record_alert(result, event=event)
                    alerts_generated.append(result)

                    # Trigger alert callback if registered
                    if self.on_alert_callback:
                        try:
                            self.on_alert_callback(result, alert_record)
                        except Exception as cb_err:
                            print(f"[Engine Callback Error]: {cb_err}")

            except Exception as det_err:
                print(f"[Engine Error in {detector.name}]: {det_err}")

        return alerts_generated

    def get_stats(self) -> Dict[str, Any]:
        """Return engine execution stats and aggregated detection numbers."""
        duration = max(time.time() - self._start_time, 0.001)
        alert_stats = self.alert_manager.get_stats()
        return {
            "packets_processed": self._packets_processed,
            "packets_per_second": round(self._packets_processed / duration, 2),
            "engine_runtime_seconds": round(duration, 2),
            "active_detectors": [d.name for d in self.detectors if d.enabled],
            **alert_stats
        }

    def export_report(self, filepath: Optional[str] = None) -> str:
        """Export session report via AlertManager with engine metadata."""
        metadata = {
            "total_packets_processed": self._packets_processed,
            "active_detectors": [d.name for d in self.detectors if d.enabled],
        }
        return self.alert_manager.export_json_report(filepath, session_metadata=metadata)

    def reset(self) -> None:
        """Reset all detector internal windows and stats."""
        for detector in self.detectors:
            detector.reset()
        self._packets_processed = 0
        self._start_time = time.time()
