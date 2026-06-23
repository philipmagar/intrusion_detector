# Intrusion Detection System (IDS) with Django Dashboard

## Overview

This project is a real-time Intrusion Detection System (IDS) built using Python, Scapy, and Django. It monitors network traffic, detects suspicious activities such as port scanning and brute-force attacks, and displays alerts through a modern web-based dashboard.

---

## Features
- **Core IDS Engine**: Captures live network traffic (IP + TCP) at the network level using Scapy.
- **Port Scan Detection**: Tracks connection frequencies per IP and flags abnormal multi-port behavior.
- **Brute-Force Detection**: Monitors repeated connection attempts from single IPs and detects brute-force signatures.
- **JSON Logging**: Persists all suspicious activities into a structured `alerts.jsonl` log.
- **Real-Time Web Dashboard**: A clean, minimalistic UI that automatically refreshes to show live threats.
- **Cross-Platform Support**: Works seamlessly on both Linux and Windows operating systems.

---

## How It Works

1. The `sniffer.py` script captures network packets using Scapy (or generates mock data if real packet sniffing isn't configured).
2. It tracks connection frequencies and port access patterns to detect anomalies.
3. Suspicious activity is immediately logged in a structured JSON format (`alerts.jsonl`).
4. The Django dashboard parses these logs, calculates real-time statistics, and visualizes them on a sleek web interface.

---

## Getting Started

### Prerequisites
- **Python 3.10+** installed on your system.
- *(For Windows Users ONLY)*: If you want to capture live network packets, you **must** install [Npcap](https://npcap.com/#download) and check the "Install Npcap in WinPcap API-compatible Mode" box during installation. Without Npcap, Scapy cannot sniff packets on Windows.

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/intrusion-detector.git
cd intrusion-detector
```

### 2. Setup Virtual Environment
It is highly recommended to use a virtual environment to avoid dependency conflicts.

**For Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**For Windows:**
```powershell
python -m venv venv_win
.\venv_win\Scripts\activate
```

### 3. Install Dependencies
Once the virtual environment is activated, install the required packages:
```bash
pip install -r requirements.txt
```

---

## Running the Application

To run the full system, you will need to open **two separate terminal windows**. Ensure your virtual environment is activated in **both** terminals before proceeding.

### Terminal 1: Start the Dashboard
Navigate into the dashboard directory and run the server:
```bash
# Make sure you are in the root 'intrusion_detector' folder first
cd dashboard
python manage.py migrate
python manage.py runserver
```
*The dashboard will be available at http://127.0.0.1:8000/ and refreshes automatically.*

### Terminal 2: Start the IDS Sniffer
In a new terminal window, activate your virtual environment, stay in the root directory, and run the sniffer:
```bash
# Linux / macOS (Requires root privileges for packet sniffing)
sudo python sniffer.py

# Windows (Run as Administrator)
python sniffer.py
```

---

## Testing the System

To see the IDS in action, you can generate network traffic using:
```bash
ping google.com
```
Or simply open multiple browser tabs and refresh pages rapidly to trigger connection anomaly alerts.

---

## Example Alert Log (`alerts.jsonl`)

```json
{"ip": "192.168.1.10", "type": "Port Scan", "time": "2026-04-21 10:00:00"}
{"ip": "192.168.1.15", "type": "Brute Force", "time": "2026-04-21 10:02:00"}
```

---

## Tech Stack
- **Backend**: Python, Scapy
- **Frontend**: Django, HTML5, Vanilla CSS
- **Database**: SQLite (Django Defaults) + JSON Log Storage

---

## Future Improvements
- Database integration (PostgreSQL) for deeper historical analysis.
- Machine learning-based anomaly detection using scikit-learn.
- Real-time alert notifications (Email / SMS / Webhooks).
