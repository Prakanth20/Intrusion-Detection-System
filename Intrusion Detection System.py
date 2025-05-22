from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

# Configuration
PORT_SCAN_THRESHOLD = 10       # Number of ports accessed to consider it a scan
TIME_WINDOW = 10               # Time window in seconds

# Dictionary to store source IP and their accessed ports with timestamps
ip_port_activity = defaultdict(list)

def detect_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        current_time = time.time()

        # Record the access time
        ip_port_activity[src_ip].append((dst_port, current_time))

        # Filter out entries older than TIME_WINDOW seconds
        ip_port_activity[src_ip] = [
            (port, t) for port, t in ip_port_activity[src_ip]
            if current_time - t <= TIME_WINDOW
        ]

        # Extract just the ports to check for unique accesses
        ports_accessed = set(port for port, _ in ip_port_activity[src_ip])

        if len(ports_accessed) > PORT_SCAN_THRESHOLD:
            print(f"[ALERT] Possible port scan detected from {src_ip}!")
            print(f"Accessed ports: {ports_accessed}")
            # Clear the entry to avoid repeated alerts
            del ip_port_activity[src_ip]

def main():
    print("Starting Intrusion Detection System...")
    print(f"Monitoring for port scans (>{PORT_SCAN_THRESHOLD} ports in {TIME_WINDOW} seconds)...")
    sniff(filter="tcp", prn=detect_scan, store=0)

if __name__ == "__main__":
    main()
