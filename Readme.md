# Intrusion Detection System (IDS) with Django Dashboard

## Overview

This project is a real-time Intrusion Detection System (IDS) built using Python, Scapy, and Django.
It monitors network traffic, detects suspicious activities such as port scanning and brute-force attacks, and displays alerts through a web-based dashboard.

---

- **Core IDS Engine**: Captures live network traffic (IP + TCP) at the network level using Scapy.
- **Port Scan Detection**: Tracks connection frequencies per IP and flags abnormal multi-port behavior.
- **Brute-Force Detection**: Monitors repeated connection attempts from single IPs and detects brute-force signatures.
- **JSON Logging**: Persists all suspicious activities into a structured `alerts.jsonl` log for analysis.
- **Real-Time Web Dashboard**: A premium, web-based Django dashboard with a dark-mode, glassmorphism UI.
- **Advanced Threat Analytics**: Interactive Chart.js visualizations mapping attack distributions and risk breakdowns.
- **Live Monitoring**: 10-second auto-refreshing interface with live counters, unique IP tracking, and "today" specific filtering.
- **Actionable Insights**: Generates searchable logs, top threat actor lists, and risk severity indicators.

---

## How It Works

1. The system captures packets using Scapy
2. Extracts source IP and protocol information
3. Tracks connection frequency and port access patterns
4. Detects:
   - Port scanning behavior
   - Brute-force attempts
5. Logs suspicious activity in structured JSON format
6. Django dashboard parses logs, calculates real-time statistics, and displays them on a premium web interface

---

## Tech Stack

- **Backend**: Python, Scapy
- **Frontend**: Django, HTML5, CSS3 (Modern UI)
- **Data**: JSON Log Storage
- **Typography**: Google Fonts (Inter)

---

## Project Structure

```bash
intrusion_detector/
 ├── dashboard/        # Django project
 ├── monitor/          # Django app
 ├── sniffer.py        # IDS core logic
 ├── alerts.jsonl      # Generated alerts
 ├── sample_alerts.json # Example logs (optional)
 ├── requirements.txt
 ├── README.md
 └── .gitignore
```

---

## How to Run

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/intrusion-detector.git
cd intrusion-detector
```

---

### 2. Setup virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

---

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

### 4. Run IDS (Terminal 1)

```bash
sudo python sniffer.py
```

---

### 5. Run Dashboard (Terminal 2)

```bash
cd dashboard
python manage.py migrate
python manage.py runserver
```

---

### 6. Open in browser

http://127.0.0.1:8000/

---

## Testing

Generate traffic using:

```bash
ping google.com
```

Or:

- Open multiple browser tabs
- Refresh pages rapidly

---

## Example Alerts

```json
{"ip": "192.168.1.10", "type": "Port Scan", "time": "2026-04-21 10:00:00"}
{"ip": "192.168.1.15", "type": "Brute Force", "time": "2026-04-21 10:02:00"}
```

---

## Learning Outcomes

- Understanding of network packets (TCP/IP)
- Real-time traffic monitoring
- Detection of suspicious patterns
- Intrusion detection system design
- Django web application development



## Future Improvements

- Database integration (SQLite/PostgreSQL) for historical analysis
- Machine learning-based anomaly detection
- Alert notifications (email or SMS)
- Network visualization maps

---
