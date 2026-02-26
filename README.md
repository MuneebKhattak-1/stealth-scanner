# 🔍 StealthScan v1.1 — Python Stealth Network Scanner

<div align="center">

[![Stars](https://img.shields.io/github/stars/MuneebKhattak-1/stealth-scanner?style=social)](https://github.com/MuneebKhattak-1/stealth-scanner/stargazers)
[![Forks](https://img.shields.io/github/forks/MuneebKhattak-1/stealth-scanner?style=social)](https://github.com/MuneebKhattak-1/stealth-scanner/network/members)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-blue?logo=linux)](https://www.kali.org/)
[![Made With](https://img.shields.io/badge/Made%20with-Scapy-green)](https://scapy.net/)

**A powerful, modular Python network reconnaissance tool for Kali Linux.**  
SYN stealth scanning · OS fingerprinting · Decoy injection · Packet fragmentation · HTML reports

</div>

---

> ⚠️ **LEGAL DISCLAIMER**: For authorized penetration testing ONLY.  
> Use ONLY on systems you own or have explicit written permission to scan.  
> Unauthorized use is illegal and unethical.

---

## ✨ Features

| Feature | Detail |
|---|---|
| **TCP Connect Scan** | No root required |
| **SYN Stealth Scan** | Half-open scan via scapy (root required) |
| **UDP Scan** | Probes UDP ports |
| **Auto OS Detection** | Port-based: 135/139/445 = Windows, 22+111 = Linux |
| **Deep OS Fingerprint** | TTL + TCP window analysis via `--os-detect` |
| **Decoy IPs** | Spoofed source packets to confuse IDS logs |
| **Packet Fragmentation** | 8-byte fragments bypass shallow IDS rules |
| **TTL Spoofing** | Mimics Windows/Linux/BSD TTL values |
| **6 Timing Profiles** | `paranoid` → `insane` (nmap-style) |
| **Banner Grabbing** | HTTP, SSH, FTP, SMTP, DB service banners |
| **Reports** | Dark-themed HTML, JSON, plain text |

---

## 🚀 Quick Start (Kali Linux)

```bash
# Clone & install
git clone https://github.com/MuneebKhattak-1/stealth-scanner.git
cd stealth-scanner
pip3 install -r requirements.txt

# Basic scan (no root)
python3 stealth_scanner.py -t 192.168.1.1

# SYN stealth scan — OS detected automatically
sudo python3 stealth_scanner.py -t 192.168.1.1 --type syn -p 135,139,445,3389 2>/dev/null

# Full stealth: decoys + fragmentation + randomized ports
sudo python3 stealth_scanner.py -t 192.168.1.1 --type syn --stealth --decoys 5 2>/dev/null

# Paranoid slow scan (evades rate-based IDS)
sudo python3 stealth_scanner.py -t 192.168.1.1 --timing paranoid --randomize 2>/dev/null

# Deep OS fingerprinting + HTML report
sudo python3 stealth_scanner.py -t 192.168.1.1 --type syn --os-detect -o report.html 2>/dev/null

# Whole subnet scan
sudo python3 stealth_scanner.py -t 192.168.1.0/24 -p top100 -o results.json 2>/dev/null
```

---

## 🖥️ Example Output

```
HOST               OS FINGERPRINT
──────────────────────────────────────────
192.168.1.17       Windows

HOST              PORT    STATE       SERVICE          BANNER
────────────────────────────────────────────────────────────────────────────────
192.168.1.17      135     open        [msrpc]
192.168.1.17      139     open        [netbios-ssn]
192.168.1.17      445     open        [smb]

[*] Scan complete in 4.32s
```

---

## 🧠 OS Detection Logic

| Priority | Method | Example |
|---|---|---|
| 1st | **Port-based** (most reliable) | 135+139+445 = Windows |
| 2nd | **TTL fingerprint** | 128=Windows, 64=Linux, 255=BSD |
| 3rd | **TCP Window size** | 8192=Windows, 29200=Linux |
| 4th | **Banner text** | `OpenSSH_8.9 Ubuntu` = Linux |

---

## ⚙️ All Options

| Flag | Description |
|---|---|
| `-t` | Target IP, hostname, or CIDR subnet |
| `-p` | Ports: `80`, `1-1024`, `22,80,443`, `top100`, `all` |
| `--type` | `connect` / `syn` / `udp` |
| `--stealth` | Enable all evasion techniques |
| `--decoys N` | Inject N spoofed source IPs |
| `--fragment` | Split packets to bypass IDS |
| `--spoof-port` | Use 80/443/53 as source port |
| `--mimic-os` | Mimic `windows` / `linux` / `bsd` TTL |
| `--timing` | `paranoid` `sneaky` `polite` `normal` `aggressive` `insane` |
| `--randomize` | Randomize port order |
| `--os-detect` | Deep OS fingerprinting |
| `--no-banner` | Skip banner grabbing |
| `-o file` | Save report (`.html` / `.json` / `.txt`) |
| `--timeout N` | Per-probe timeout (seconds) |
| `-w N` | Max concurrent workers |

---

## 📁 Project Structure

```
stealth-scanner/
├── stealth_scanner.py      # CLI entry point
├── requirements.txt
├── LICENSE
└── core/
    ├── scanner.py          # TCP/SYN/UDP engine + auto OS detection
    ├── stealth.py          # Evasion: decoys, fragmentation, TTL, timing
    ├── fingerprint.py      # OS + service fingerprinting
    └── reporter.py         # JSON / HTML / TXT reports
```

---

## 📜 License

MIT © [MuneebKhattak-1](https://github.com/MuneebKhattak-1)
