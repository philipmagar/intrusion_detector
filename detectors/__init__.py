"""
IDS Detection Modules Package.

Exports:
- DetectionResult: Standardized detection result schema
- BaseDetector: Abstract base detector class
- PortScanDetector: Vertical and horizontal scan detection
- SynFloodDetector: TCP SYN flood and half-open attack detection
- RateAnomalyDetector: Abnormal connection rates, PPS bursts, ICMP/UDP storms
- BruteForceDetector: Rapid authentication and service password brute-force detection
- SuspiciousTrafficDetector: Malicious TCP flags, C2 ports, DNS payload anomalies
"""

from .base import BaseDetector, DetectionResult
from .port_scan import PortScanDetector
from .syn_flood import SynFloodDetector
from .rate_anomaly import RateAnomalyDetector
from .brute_force import BruteForceDetector
from .suspicious_traffic import SuspiciousTrafficDetector

__all__ = [
    "BaseDetector",
    "DetectionResult",
    "PortScanDetector",
    "SynFloodDetector",
    "RateAnomalyDetector",
    "BruteForceDetector",
    "SuspiciousTrafficDetector",
]
