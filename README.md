# Basic Network Sniffer 🔍

A Python-based network packet sniffer built for the **CodeAlpha Cybersecurity Internship** (Task 1).

## Features
- Captures live network packets in real-time
- Displays Source & Destination IP addresses
- Identifies protocols (TCP, UDP, ICMP)
- Shows port numbers with service names (HTTP, HTTPS, DNS, SSH, etc.)
- Displays TCP flags (SYN, ACK, FIN, etc.)
- Shows packet payload in HEX and ASCII format
- Saves all captured packets to a log file

## Requirements
- Python 3.x
- Scapy library
- Npcap (Windows) or libpcap (Linux)

## Installation
```bash
pip install scapy
```

## Usage
Run as Administrator (Windows) or sudo (Linux):
```bash
python network_sniffer.py
```

## Author
**Rana Muhammad Hateem** | CodeAlpha Cybersecurity Internship
