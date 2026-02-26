# 🔍 StealthScan - Python Network Reconnaissance Tool for Kali Linux

## ⚠️ LEGAL DISCLAIMER
This tool is intended ONLY for authorized penetration testing and security research.
Use ONLY on networks/systems you own or have written permission to test.
Unauthorized use is illegal and unethical.

---

## Features
- **SYN Stealth Scan** – Half-open TCP scan (doesn't complete 3-way handshake)
- **Decoy Scanning** – Spoofs source IPs to obfuscate origin
- **Fragmented Packet Scan** – Splits packets to evade IDS/IPS
- **OS Fingerprinting** – Detects target OS via TTL & TCP window analysis
- **Service/Banner Grabbing** – Identifies running services and versions
- **Rate Limiting** – Slow scan mode to fly under IDS radar
- **Randomized Port Order** – Avoids sequential port scan signatures
- **Custom User-Agent** – Mimics legitimate traffic
- **IPv6 Support**
- **JSON/HTML Report Output**

## Requirements
```
pip install -r requirements.txt
```

## Usage
```bash
# Basic stealth scan
sudo python3 stealth_scanner.py -t 192.168.1.1

# Full stealth scan with decoys and fragmentation
sudo python3 stealth_scanner.py -t 192.168.1.1 --stealth --decoys 5 --fragment

# Scan specific port range slowly
sudo python3 stealth_scanner.py -t 192.168.1.0/24 -p 1-1024 --slow --randomize

# Output results to JSON
sudo python3 stealth_scanner.py -t 192.168.1.1 -o report.json

# OS fingerprinting
sudo python3 stealth_scanner.py -t 192.168.1.1 --os-detect
```

## Directory Structure
```
stealth_scanner/
├── stealth_scanner.py      # Main entry point
├── core/
│   ├── scanner.py          # Core scanning engine
│   ├── stealth.py          # Evasion techniques
│   ├── fingerprint.py      # OS/service fingerprinting
│   └── reporter.py         # Output formatting
├── requirements.txt
└── README.md
```
