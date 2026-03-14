# 🔍 StealthScan v1.1 — Python Stealth Network Scanner

<div align="center">

[![Stars](https://img.shields.io/github/stars/MuneebKhattak-1/stealth-scanner?style=social)](https://github.com/MuneebKhattak-1/stealth-scanner/stargazers)
[![Forks](https://img.shields.io/github/forks/MuneebKhattak-1/stealth-scanner?style=social)](https://github.com/MuneebKhattak-1/stealth-scanner/network/members)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-blue?logo=linux)](https://www.kali.org/)
[![Made With](https://img.shields.io/badge/Made%20with-Scapy-green)](https://scapy.net/)

**A powerful, modular Python network reconnaissance tool with CLI & GUI.**  
SYN stealth scanning · OS fingerprinting · Decoy injection · Packet fragmentation · Zenmap-style GUI · HTML reports

</div>

---

> ⚠️ **LEGAL DISCLAIMER**: For authorized penetration testing ONLY.  
> Use ONLY on systems you own or have explicit written permission to scan.  
> Unauthorized use is illegal and unethical.

---

## ✨ Features

| Feature | Detail |
|---|---|
| **🖥️ Zenmap-Style GUI** | Dark-themed graphical interface with tabbed results |
| **CLI + GUI** | Use from terminal or launch the graphical interface |
| **TCP Connect Scan** | No root required |
| **SYN Stealth Scan** | Half-open scan via scapy (root required) |
| **UDP Scan** | Probes UDP ports |
| **🔍 SMB OS Discovery** | Extracts exact Windows build via SMB2/NTLM (no root needed) |
| **Auto OS Detection** | Port-based + ping TTL + banner analysis |
| **Deep OS Fingerprint** | TTL + TCP window + SMB + banner combined analysis |
| **Decoy IPs** | Spoofed source packets to confuse IDS logs |
| **Packet Fragmentation** | 8-byte fragments bypass shallow IDS rules |
| **TTL Spoofing** | Mimics Windows/Linux/BSD TTL values |
| **6 Timing Profiles** | `paranoid` → `insane` (nmap-style) |
| **Banner Grabbing** | HTTP, SSH, FTP, SMTP, DB service banners |
| **Reports** | Dark-themed HTML, JSON, plain text |

---

## 🖥️ GUI Mode (Zenmap-Style)

StealthScan includes a full **graphical interface** inspired by Zenmap — no extra dependencies needed (uses Python's built-in `tkinter`).

```bash
# Launch the GUI
python3 stealth_scanner_gui.py
```

### GUI Features

- **🎨 Dark hacker theme** — sleek dark interface with cyan/green accents
- **📋 Scan profiles** — Quick Scan, Intense, SYN Stealth, Full Stealth, UDP, Full Port Scan
- **⚡ One-click scanning** — enter target, pick a profile, click Scan
- **📊 4 tabbed views:**
  - **Scan Output** — real-time colored log (like Zenmap's Nmap Output tab)
  - **Ports / Hosts** — sortable table with Host, Port, State, Service, Banner, OS
  - **Host Details** — per-host OS fingerprint card with open ports summary
  - **Topology** — visual canvas with host nodes colored by OS
- **💾 Save reports** — File → Save as HTML / JSON / TXT
- **🔄 Live progress** — progress bar, timer, and open port counter in status bar
- **📝 Command bar** — shows equivalent CLI command for each profile

### GUI Scan Profiles

| Profile | Type | Ports | Timing | Stealth |
|---|---|---|---|---|
| Quick Scan | TCP Connect | top100 | Normal | Off |
| Intense Scan | TCP Connect | 1-1024 | Aggressive | Off (+OS) |
| SYN Stealth Scan | SYN | top100 | Sneaky | On |
| Full Stealth | SYN | top100 | Paranoid | On (decoys+frag+spoof) |
| UDP Scan | UDP | top100 | Normal | Off |
| Full Port Scan | TCP Connect | all 65535 | Aggressive | Off (+OS) |

---

## 🚀 Quick Start

### Install

```bash
git clone https://github.com/MuneebKhattak-1/stealth-scanner.git
cd stealth-scanner
pip3 install -r requirements.txt
```

### GUI Mode

```bash
python3 stealth_scanner_gui.py
```

### CLI Mode

```bash
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

## 🖥️ Example Output (CLI)

```
[*] Running OS detection...
  192.168.1.17 → Windows 10 / Server 2019 (Build 19045) (via SMB)

HOST              PORT    STATE       SERVICE          BANNER
────────────────────────────────────────────────────────────────────────────────
192.168.1.17      135     open        [msrpc]
192.168.1.17      139     open        [netbios-ssn]
192.168.1.17      445     open        [smb]
192.168.1.17      3389    open        [rdp]

HOST               OS FINGERPRINT
──────────────────────────────────────────
192.168.1.17       Windows 10 / Server 2019 (Build 19045)

[*] Scan complete in 4.32s
```

---

## 🧠 OS Detection Logic

StealthScan uses **multiple detection methods** and picks the most specific result:

| Priority | Method | No Root? | Example Output |
|---|---|---|---|
| 1st | **SMB2/NTLM negotiation** | ✅ | `Windows 11 (Build 22621)` |
| 2nd | **Banner analysis** | ✅ | `Ubuntu 22.04 LTS`, `Debian 12` |
| 3rd | **TTL + TCP Window** | ⚠️ | `Windows 10 (v1703+)`, `Linux 5.x` |
| 4th | **Port-based** | ✅ | `Windows` (135/445), `Linux` (22+111) |
| 5th | **TTL only (ping)** | ✅ | `Windows` (128), `Linux` (64) |

> 💡 **No root required!** SMB detection auto-runs when port 445 is open, and ping TTL works without privileges on most systems. Use `--os-detect` for additional scapy-based deep probing (requires root).

---

## ⚙️ CLI Options

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
├── stealth_scanner_gui.py  # GUI entry point (Zenmap-style)
├── requirements.txt
├── LICENSE
├── core/
│   ├── scanner.py          # TCP/SYN/UDP engine + auto OS detection
│   ├── stealth.py          # Evasion: decoys, fragmentation, TTL, timing
│   ├── fingerprint.py      # OS + service fingerprinting
│   └── reporter.py         # JSON / HTML / TXT reports
└── gui/
    ├── app.py              # Main GUI window + layout
    ├── scan_profiles.py    # Pre-defined scan profiles
    ├── scan_thread.py      # Background scan thread
    └── results_view.py     # Tabbed result views (Output, Ports, Host, Topology)
```

---

## 📜 License

MIT © [MuneebKhattak-1](https://github.com/MuneebKhattak-1)
