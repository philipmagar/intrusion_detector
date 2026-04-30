# Intrusion Detection System (IDS) with Django Dashboard

## Overview

This project is a real-time Intrusion Detection System (IDS) built using Python, Scapy, and Django.
It monitors network traffic, detects suspicious activities such as port scanning and brute-force attacks, and displays alerts through a web-based dashboard.

---

## Features

### Day 1: Packet Sniffer

- Captures live network traffic using Scapy
- Displays packet summaries in real-time
- Works at network level (IP + TCP packets)

### Day 2: Port Scan Detection

- Tracks activity of each IP address
- Detects abnormal behavior (multiple requests in short time)
- Raises alert for possible port scanning
- Logs suspicious activity

### Day 3: Brute-Force Attack Detection

- Monitors repeated connection attempts from same IP
- Detects abnormal connection frequency
- Flags potential brute-force behavior
- Logs alerts in structured JSON format

### Day 4: Enhanced Django Dashboard (Web Interface)

- Built a web-based dashboard using Django
- **Live Updating**: Real-time monitoring with 5-second auto-refresh
- **Security Analytics**: Total alerts counter and attack type breakdown
- **Premium UI**: Modern dark-mode interface with Glassmorphism and Inter typography
- Displays detected attacks in a structured, searchable table
- Reads alerts from log file and presents them visually

### Day 5: Advanced Threat Analytics & Visualization

- **Interactive Charts**: Integrated Chart.js for real-time attack distribution over time.
- **Threat Analytics**: Added top threat actors list and doughnut charts for risk breakdown.
- **"Today" Filtering**: Automatically filters metrics and charts to show data for the current day.
- **Live Counters**: Extended real-time badges for unique attacker IPs and daily alert counts.

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
 ├── alerts.json       # Generated alerts
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

---

## Project Progress Summary

- Day 1: Packet sniffing
- Day 2: Port scan detection
- Day 3: Brute-force detection
- Day 4: Web dashboard integration
- Day 5: Advanced threat analytics & visualization

---

## Future Improvements

- Database integration (SQLite/PostgreSQL) for historical analysis
- Machine learning-based anomaly detection
- Alert notifications (email or SMS)
- Network visualization maps

---
