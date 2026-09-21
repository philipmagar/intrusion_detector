"""
Base Detector and Standardized Detection Result Interface.

Defines the contract for all modular intrusion detection components,
ensuring consistent fields: attack type, evidence, severity, confidence, and triggered rule.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, Any, Optional, List
import json


@dataclass
class DetectionResult:
    """
    Standardized result emitted by any IDS detector module.
    
    Attributes:
        attack_type (str): Name/classification of the detected attack (e.g. 'Port Scan', 'SYN Flood')
        severity (str): Threat severity level: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
        confidence (float): Confidence score between 0.0 (uncertain) and 1.0 (definite)
        triggered_rule (str): Internal rule identifier that triggered the alert
        evidence (dict): Contextual packet statistics, addresses, ports, and trigger justification
        timestamp (str): ISO formatted detection timestamp
        timestamp_epoch (float): Epoch timestamp of detection
    """
    attack_type: str
    severity: str
    confidence: float
    triggered_rule: str
    evidence: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    timestamp_epoch: float = field(default_factory=lambda: datetime.now().timestamp())

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary representation."""
        return asdict(self)

    def to_json(self, indent: Optional[int] = None) -> str:
        """Convert result to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class BaseDetector(ABC):
    """
    Abstract Base Class for all Intrusion Detection Modules.
    """

    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled

    @abstractmethod
    def process_event(self, event) -> Optional[DetectionResult]:
        """
        Evaluate a standardized SecurityEvent and return a DetectionResult if a threat is detected.
        
        Args:
            event (SecurityEvent): Standardized security event from packet_parser.py
            
        Returns:
            Optional[DetectionResult]: Detection result object if threat detected, otherwise None.
        """
        pass

    def reset(self) -> None:
        """Reset internal tracking state/history windows."""
        pass
