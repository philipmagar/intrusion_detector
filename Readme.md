# Modular Intrusion Detection System (IDS) with Real-Time Dashboard

## Overview

A high-performance, modular Intrusion Detection System (IDS) built with Python, Scapy, and Django. It normalizes network traffic into standardized security events, evaluates packets across specialized detection modules (port scans, SYN floods, traffic rate anomalies, brute-force patterns, and suspicious TCP flag evasions), persists alerts to local JSON/JSONL, maintains real-time in-memory tracking, and exports comprehensive session reports to JSON.

---

## Modular Detection Architecture

The IDS employs decoupled, extensible detection modules located in [`detectors/`](file:///c:/Users/phili/OneDrive/Desktop/github%20project/vulnerabilityassestment/intrusion_detector/detectors/):

| Detector Module | Target Attack Vector | Detection Heuristic & Rules | Severity |
| :--- | :--- | :--- | :--- |
| **Port Scan Detector** | Vertical Port Scan & Horizontal Sweep | Tracks unique destination ports per target (> 8 ports in 10s) and multi-host probing | `HIGH` / `MEDIUM` |
| **SYN Flood Detector** | TCP SYN Flood DoS / DDoS | Monitors SYN burst rates (> 25 pps) and half-open SYN-to-ACK imbalance ratios | `CRITICAL` / `HIGH` |
| **Rate Anomaly Detector** | Abnormal Connection Rates & Floods | Detects sudden PPS bursts (> 30 pps), ICMP Ping Floods, and UDP storms | `CRITICAL` / `HIGH` |
| **Brute Force Detector** | Authentication & Credential Attacks | Detects rapid connection/auth bursts on SSH (22), RDP (3389), FTP (21), Telnet (23), DBs, and Web logins | `HIGH` / `MEDIUM` |
| **Suspicious Traffic Detector** | Evasion & Malicious Flag Combos | Detects Xmas scans (`FIN+PSH+URG`), Null scans (`0 flags`), `SYN+FIN` illegal combos, FIN scans, and known C2 backdoor ports (4444, 31337, etc.) | `CRITICAL` / `HIGH` |

---

## Standardized Detection Result & Alert Schema

Every detector emits a consistent `DetectionResult` structure with full contextual evidence:

```json
{
  "ip": "192.168.1.100",
  "type": "Port Scan (Vertical)",
  "time": "2026-09-21 20:30:00",
  "attack_type": "Port Scan (Vertical)",
  "severity": "HIGH",
  "confidence": 0.95,
  "triggered_rule": "RULE_PORT_SCAN_VERTICAL_THRESHOLD",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "src_port": 51234,
  "dst_port": 80,
  "protocol": "TCP",
  "packet_size": 60,
  "flags": "SYN",
  "evidence": {
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.1",
    "distinct_ports_count": 10,
    "ports_targeted": [21, 22, 23, 25, 53, 80, 110, 143, 443, 8080],
    "window_seconds": 10.0,
    "packet_stats": {
      "total_probes_in_window": 10,
      "distinct_ports": 10,
      "probe_rate_pps": 1.0,
      "last_packet_size": 60,
      "tcp_flags": "SYN"
    },
    "details": "Host 192.168.1.100 probed 10 distinct ports on 10.0.0.1 within 10.0s."
  }
}
```

---

## Alert Storage & JSON Reporting

- **Local JSONL Logging (`alerts.jsonl`)**: Persistent append-only JSON Lines stream containing all incident details, fully backwards-compatible with the Django dashboard.
- **In-Memory Ring Buffer**: Thread-safe cache storing recent alerts for zero-latency dashboard queries and real-time monitoring.
- **Structured JSON Scan Reports**: Automatically exports session summary reports (`scan_report_<timestamp>.json`) upon completion or graceful shutdown (`Ctrl+C`).

---

## Getting Started

### 1. Prerequisites & Virtual Environment
- **Python 3.10+**
- *(Windows Only)*: [Npcap](https://npcap.com/#download) with WinPcap compatibility enabled for live packet sniffing.

```powershell
# Activate your virtual environment
.\venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt
```

### 2. Running Unit Tests
Validate all detector modules, alert persistence, and report exporting:
```powershell
python -m unittest test_detectors.py test_packet_parser.py
```

### 3. Running Example Attack Simulation
Run the standalone demonstration script:
```powershell
python example_event_conversion.py
```

### 4. Running the Live IDS Engine & Dashboard
**Terminal 1: Start Dashboard**
```powershell
cd dashboard
python manage.py runserver
```

**Terminal 2: Start Sniffer / Attack Simulator**
```powershell
python sniffer.py
```

---

## Project Structure

```
intrusion_detector/
├── detectors/
│   ├── __init__.py               # Detector module exports
│   ├── base.py                   # BaseDetector ABC & DetectionResult dataclass
│   ├── port_scan.py              # Vertical & horizontal scan detection
│   ├── syn_flood.py              # TCP SYN flood & half-open tracking
│   ├── rate_anomaly.py           # Traffic burst, PPS spike, ICMP/UDP floods
│   ├── brute_force.py            # SSH, RDP, FTP, DB password brute-force
│   └── suspicious_traffic.py     # Xmas, Null, SYN+FIN scans, C2 ports
├── alert_manager.py              # Local JSON logging, in-memory cache, JSON report exporter
├── engine.py                     # Central IDS coordination pipeline
├── packet_parser.py              # Scapy packet to SecurityEvent normalizer
├── sniffer.py                    # Live sniffing & simulated attack engine
├── example_event_conversion.py   # Demonstration script
├── test_detectors.py             # Unit tests for all detectors & storage
├── test_packet_parser.py         # Unit tests for packet parser
├── alerts.jsonl                  # Local JSON alert log
└── dashboard/                    # Django real-time monitoring dashboard
```
