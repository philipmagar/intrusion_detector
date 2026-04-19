# ntrusion Detection System (IDS)

##  Overview

This project is a **basic Intrusion Detection System (IDS)** built using Python and Scapy.
It monitors real-time network traffic and detects suspicious activities such as **port scanning attacks**.

---

##  Features (Completed So Far)

### Day 1: Packet Sniffer

- Captures live network traffic using Scapy
- Displays packet summaries in real-time
- Works at network level (IP + TCP packets)

### Day 2: Port Scan Detection

- Tracks activity of each IP address
- Detects abnormal behavior (multiple requests in short time)
- Raises alert for possible port scanning
- Logs suspicious activity to a file (`alerts.log`)

### Day 3: Brute-Force Attack Detection
- Monitors repeated connection attempts from same IP
- Detects abnormal connection frequency
- Flags potential brute-force behavior

---

## How It Works

1. The system captures packets using Scapy
2. Extracts:

   * Source IP
   * Protocol (TCP/IP)
3. Stores timestamps of incoming packets
4. If an IP sends too many requests within a short time:

   *  Alert is triggered
   * Activity is logged

---

##  Tech Stack

* Python
* Scapy
* Linux (WSL / Ubuntu recommended)

---

## 📂 Project Structure

```
intrusion_detector/
 ├── sniffer.py
 ├── alerts.log
 └── venv/
```

---

## ▶️ How to Run

### 1. Activate virtual environment

```
source venv/bin/activate
```

### 2. Run the IDS (requires root privileges)

```
sudo python sniffer.py
```

---

##  Testing

Generate traffic by:

```
ping google.com
```

Or browsing websites.

---

##  Example Alert

```
[ALERT] Possible port scan detected from 192.168.x.x
```

---

##  Learning Outcomes

* Understanding of network packets (TCP/IP)
* Real-time traffic monitoring
* Detection of suspicious patterns
* Basics of intrusion detection systems

-----
