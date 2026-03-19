# 👻 Ghost-Net: Real-time Network Intrusion Detection

Ghost-Net is a lightweight, Python-powered Network Intrusion Detection System (IDS) focused on identifying **TCP SYN scans**. This project simulates a professional security dashboard for real-time network traffic monitoring.

---

## 🚀 Key Features

- **Live Traffic Monitoring** — captures TCP SYN packets (connection attempts) using the Scapy library.
- **Dynamic Threat Leveling** — automatically evaluates the risk level of IP addresses based on request frequency.
- **Visual Terminal UI** — clean dashboard using ASCII graphics, color coding, and live event logging.
- **Incident Reporting** — automatically generates a forensic report upon stopping the monitor.

---

## 🛠️ Technical Details

Ghost-Net detects **Half-open scanning** — a technique used by attackers to map open ports without completing the TCP handshake:

```
Attacker  →  SYN     →  Target
Target    →  SYN-ACK →  Attacker
Attacker ignores ACK   ← Ghost-Net flags the threat
```

### Requirements

| Dependency  | Description               |
|-------------|---------------------------|
| Python 3.x  | Core runtime              |
| Scapy       | `pip install scapy`       |
| sudo / root | Access to network adapter |

---

## 📦 How to Run

**1. Start Ghost-Net (defender):**
```bash
sudo python3 sentinel_dashboard.py
```

**2. Start the attack simulation (attacker):**
```bash
sudo python3 attacker.py
```

---

## 📊 Incident Report

After pressing `Ctrl+C`, Ghost-Net automatically generates `sentinel_incident_report.txt` — a structured table of all captured threats, including IP addresses, target ports, and connection attempt counts.

---

*Created as part of Cyber Security studies on a Latitude E6440.*
