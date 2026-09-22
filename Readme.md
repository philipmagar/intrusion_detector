#   SentinelFlow IDS — Modular Network Intrusion Detection System

> **A lightweight, modular Network Intrusion Detection System (IDS) that normalizes raw network packets in real-time, detects multi-vector cyberattacks using sliding-window heuristics, and streams live security alerts to an auto-refreshing web dashboard.**

---
 
##  Demo & Visual Overview

---

## Features

- **Standardized Packet Normalization**: Converts diverse L2–L4 Scapy network packets into unified `SecurityEvent` objects with IP, port, protocol, size, flags, and epoch timestamps.
-  **Modular Threat Detectors**:
  - **Port Scan Detector**: Detects vertical probing (> 8 ports per target) and horizontal sweeps (> 5 hosts per port).
  - **SYN Flood Detector**: Catches TCP SYN bursts (> 25 pps) and half-open connection table exhaustion.
  - **Rate Anomaly Detector**: Identifies abnormal traffic volume spikes, ICMP ping floods, and UDP storms.
  - **Brute-Force Pattern Detector**: Flags rapid credential attacks on SSH (22), RDP (3389), FTP (21), Telnet (23), DBs, and Web logins.
  - **Suspicious Traffic Detector**: Catches stealth evasions (`Xmas`, `Null`, illegal `SYN+FIN`, `FIN-only`) and known malware C2 backdoor ports (4444, 31337).
-  **Dual-Layer JSON Storage**:
  - Persistent, append-only **JSON Lines (`alerts.jsonl`)** log containing rich contextual evidence and packet stats.
  - Thread-safe **in-memory ring buffer** for instant, low-latency queries.
  - **JSON Scan Reports** automatically exported on shutdown with comprehensive session metrics.
-  **Real-Time Web Dashboard**: A modern, responsive Django web interface that auto-refreshes to show threat metrics, attack breakdowns, and top offender IPs.
-  **Zero-Dependency Simulation Mode**: Includes a built-in attack generator to test and demonstrate all detectors on any machine without needing specialized packet capture drivers.

---

## Tech Stack

- **Core Logic**: Python 3.10+
- **Packet Ingestion & Dissection**: Scapy
- **Web Dashboard**: Django, HTML5, Modern CSS (CSS Grid/Flexbox, Custom Properties)
- **Data Persistence**: JSON Lines (`alerts.jsonl`), Structured JSON Reports
- **Testing & Benchmarking**: Python `unittest`, High-Resolution Performance Timers (`time.perf_counter`)

---

##  Controlled Lab Benchmark & Evaluation Results

Tested across **18 controlled lab scenarios** (13 cyberattack variants and 5 benign background traffic baselines):

| Metric | Result | Benchmark Target | Status |
| :--- | :--- | :--- | :--- |
| **Detection Accuracy** | **100.0%** | $\ge 95\%$ | ✅ Exceeded |
| **Precision** | **100.0%** | $\ge 90\%$ | ✅ Exceeded (Zero False Alarms) |
| **Recall / TPR** | **100.0%** (13/13) | $\ge 95\%$ | ✅ Exceeded |
| **False Positive Rate (FPR)** | **0.0%** (0/5) | $\le 2\%$ | ✅ Exceeded |
| **F1-Score** | **1.0000** | $\ge 0.95$ | ✅ Exceeded |
| **Mean Detection Latency** | **0.12 ms** | $\le 10\text{ ms}$ | ✅ Sub-millisecond |
| **95th Percentile Latency (P95)** | **0.24 ms** | $\le 20\text{ ms}$ | ✅ Sub-millisecond |

### Lab Evaluation Matrix

| Test Scenario | Traffic Type | Packets | Detection | Latency | Severity | Risk Score |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Vertical Port Scan (Nmap -T4)** | `ATTACK` | 13 ports | **DETECTED** | `0.15 ms` | `HIGH` | **66.0** |
| **Stealth Web Port Scan** | `ATTACK` | 10 ports | **DETECTED** | `0.12 ms` | `MEDIUM` | **41.0** |
| **Horizontal Subnet Sweep (SMB 445)** | `ATTACK` | 9 targets | **DETECTED** | `0.08 ms` | `MEDIUM` | **39.0** |
| **TCP SYN Flood DoS (Port 80)** | `ATTACK` | 35 pkts | **DETECTED** | `0.25 ms` | `CRITICAL`| **94.0** |
| **ICMP Echo (Ping) Flood** | `ATTACK` | 25 pkts | **DETECTED** | `0.18 ms` | `HIGH` | **67.5** |
| **UDP Volumetric Storm** | `ATTACK` | 40 pkts | **DETECTED** | `0.22 ms` | `HIGH` | **66.0** |
| **High-PPS Connection Burst** | `ATTACK` | 35 pkts | **DETECTED** | `0.20 ms` | `HIGH` | **63.8** |
| **SSH Brute-Force Password Attack** | `ATTACK` | 15 pkts | **DETECTED** | `0.14 ms` | `HIGH` | **63.8** |
| **RDP Remote Desktop Login Attack** | `ATTACK` | 14 pkts | **DETECTED** | `0.13 ms` | `HIGH` | **63.8** |
| **TCP Xmas Scan (`FIN+PSH+URG`)** | `ATTACK` | 1 pkt | **DETECTED** | `0.02 ms` | `HIGH` | **73.5** |
| **TCP Null Scan (`0 flags`)** | `ATTACK` | 1 pkt | **DETECTED** | `0.02 ms` | `HIGH` | **71.3** |
| **Illegal SYN+FIN Combination** | `ATTACK` | 1 pkt | **DETECTED** | `0.02 ms` | `CRITICAL`| **99.0** |
| **Malware C2 Port (4444)** | `ATTACK` | 1 pkt | **DETECTED** | `0.02 ms` | `HIGH` | **66.0** |
| **Benign HTTPS Web Browsing** | `BENIGN` | 3 pkts | **CLEAN** | `0.03 ms` | `NONE` | **0.0** |
| **Benign DNS Resolution (UDP 53)** | `BENIGN` | 4 queries| **CLEAN** | `0.04 ms` | `NONE` | **0.0** |
| **Benign Single SSH Admin Login** | `BENIGN` | 2 pkts | **CLEAN** | `0.02 ms` | `NONE` | **0.0** |
| **Benign ICMP Health Ping** | `BENIGN` | 4 pkts | **CLEAN** | `0.03 ms` | `NONE` | **0.0** |
| **Benign Cloud API Traffic** | `BENIGN` | 3 calls | **CLEAN** | `0.03 ms` | `NONE` | **0.0** |

---

##  Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/philipmagar/intrusion_detector.git
cd intrusion_detector
```

### 2. Setup Virtual Environment
```powershell
# Windows
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

*(Optional for Live Packet Sniffing on Windows)*: Install [Npcap](https://npcap.com/#download) and select **"Install Npcap in WinPcap API-compatible Mode"**.

---

##  Usage

### Option 1: Run Web Dashboard & IDS Engine

Open **two separate terminal windows**:

**Terminal 1 — Start the Dashboard:**
```powershell
cd dashboard
python manage.py runserver
```
> Open browser at: **`http://127.0.0.1:8000/`**

**Terminal 2 — Start the IDS Sniffer / Attack Simulator:**
```powershell
python sniffer.py
```
> Press **`Ctrl + C`** anytime to stop and export a JSON session report (`scan_report_<timestamp>.json`).

---

### Option 2: Run Standalone Attack Simulation Demo
```powershell
python example_event_conversion.py
```

---

### Option 3: Run Automated Tests & Benchmark Suite
```powershell
# Run Unit Tests
python -m unittest test_detectors.py test_packet_parser.py

# Run Controlled Lab Evaluation
python benchmark_lab_tests.py
```

---

##  Project Structure

```
intrusion_detector/
├── detectors/                    # Modular Detection Engine
│   ├── __init__.py               # Package exports
│   ├── base.py                   # BaseDetector ABC & DetectionResult dataclass
│   ├── port_scan.py              # Vertical & horizontal scan detection
│   ├── syn_flood.py              # TCP SYN flood & half-open DoS detection
│   ├── rate_anomaly.py           # Traffic bursts, PPS spikes, ICMP/UDP storms
│   ├── brute_force.py            # SSH, RDP, FTP credential brute-force
│   └── suspicious_traffic.py     # Xmas, Null, SYN+FIN scans, C2 backdoor ports
├── alert_manager.py              # Local JSON logging, in-memory buffer, JSON export
├── engine.py                     # Central IDS coordination pipeline
├── packet_parser.py              # Scapy packet to SecurityEvent normalizer
├── sniffer.py                    # Live sniffing & multi-vector attack simulator
├── benchmark_lab_tests.py        # Controlled lab evaluation & benchmark suite
├── example_event_conversion.py   # Standalone demo script
├── test_detectors.py             # Unit tests for all detectors & storage
├── test_packet_parser.py         # Unit tests for packet parser
├── alerts.jsonl                  # Local JSON alert log
└── dashboard/                    # Django real-time monitoring dashboard
    ├── manage.py
    ├── dashboard/                # Django project config (settings, urls)
    └── monitor/                  # Monitor app (views, templates, charts)
```

---

##  What I Learned

1. **Network Protocol Dissection**: Gained a deep understanding of TCP flags (SYN, ACK, FIN, RST, PSH, URG), handshake lifecycles, and how attackers craft illegal combinations (e.g. Xmas and Null scans) to bypass basic packet filters.
2. **Sliding-Window Anomaly Heuristics**: Designed and tuned time-window algorithms to differentiate legitimate network bursts (e.g., loading complex web apps) from volumetric attacks (e.g., SYN/ICMP floods).
3. **Decoupled Architecture & Extensibility**: Built a modular detector interface (`BaseDetector`) allowing new detection rules to be added without modifying the core pipeline.
4. **Thread-Safe Data Structures**: Managed thread-safe in-memory ring buffers (`deque`) with local file persistence for low-latency dashboard streaming.

---

##  Future Improvements

- [ ] **Machine Learning-Based Anomaly Detection**: Integrate Isolation Forests / Autoencoders to detect zero-day traffic anomalies without static thresholds.
- [ ] **Automated Incident Response (IPS)**: Add firewall integration (iptables / Windows Defender Firewall) to automatically block offender IPs.
- [ ] **Live WebSockets Streaming**: Replace meta-refresh polling with Django Channels / WebSockets for sub-second alert updates.
- [ ] **PCAP Export**: Add raw packet capture export (`.pcap`) for Wireshark forensics investigation.
