# 🛡️ Intrusion Detection System (IDS)

This Python-based Intrusion Detection System monitors network traffic in real-time to detect potential **port scanning attacks** using `scapy`. It identifies suspicious behavior by tracking the number of unique ports accessed by each IP within a short time frame.

## 🚨 How It Works

The system uses a simple heuristic:
If a single IP address attempts to connect to more than a specified number of **different TCP ports** within a **short time window**, it likely indicates a **port scan** attempt — a common reconnaissance technique used before a cyberattack.

## 🧰 Features

* Real-time packet sniffing using Scapy
* Detects port scanning activity
* Customizable detection thresholds
* Lightweight and easy to run on local machines or servers

## 📦 Requirements

Install Scapy before running the IDS:

```bash
pip install scapy
```

> ⚠️ You must run the script with **administrator/root privileges** to sniff packets:
>
> * On Linux/macOS: `sudo python ids.py`
> * On Windows: Run the terminal as Administrator

## ⚙️ Configuration

You can modify these parameters in the script to tune detection sensitivity:

```python
PORT_SCAN_THRESHOLD = 10   # Number of ports accessed before triggering an alert
TIME_WINDOW = 10           # Time window (in seconds) to evaluate activity
```

## 🚀 Usage

1. **Run the Script:**

```bash
sudo python ids.py
```

2. **Output Example:**

```
[ALERT] Possible port scan detected from 192.168.1.101!
Accessed ports: {21, 22, 23, 25, 80, 110, 143, 443, 8080, 3306, 5432}
```

## 🧪 Testing

You can test the system using tools like:

* [Nmap](https://nmap.org/)
* Custom port scanning scripts

Example Nmap command:

```bash
nmap -p 1-1000 <your-local-IP>
```

## 🔒 Disclaimer

This tool is meant for **educational and monitoring purposes only**. Unauthorized scanning of networks that you do not own or have explicit permission to test is illegal and unethical.
