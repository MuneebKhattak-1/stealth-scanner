# 🔍 StealthScan v1.1 — Python Network Reconnaissance Tool

## ⚠️ LEGAL DISCLAIMER
For authorized penetration testing ONLY. Use only on networks/systems you own or have written permission to test.

---

## Features
| Feature | Detail |
|---|---|
| **TCP Connect Scan** | No root required |
| **SYN Stealth Scan** | Half-open scan via scapy (root required) |
| **UDP Scan** | Probes UDP ports |
| **Auto OS Detection** | Port-based (135/139/445 = Windows, 22+111 = Linux) — shown automatically |
| **Deep OS Fingerprint** | TTL + TCP window via `--os-detect` |
| **Decoy IPs** | Injects spoofed source packets to confuse IDS logs |
| **Packet Fragmentation** | 8-byte fragments bypass shallow IDS signatures |
| **TTL Spoofing** | Mimics Windows/Linux/BSD TTL values |
| **Timing Profiles** | paranoid → insane (6 nmap-style levels) |
| **Banner Grabbing** | HTTP, SSH, FTP, SMTP, DB banners |
| **Reports** | JSON, dark-themed HTML, plain text |

---

## Requirements
```bash
pip install -r requirements.txt
```

---

## Usage

### Basic scan (no root)
```bash
python3 stealth_scanner.py -t 192.168.1.1
```

### SYN stealth scan — OS shown automatically
```bash
sudo python3 stealth_scanner.py -t 192.168.1.1 --type syn -p 135,139,445,3389 2>/dev/null
```

### Full stealth mode
```bash
sudo python3 stealth_scanner.py -t 192.168.1.1 --type syn --stealth --decoys 5 2>/dev/null
```

### Deep OS fingerprinting
```bash
sudo python3 stealth_scanner.py -t 192.168.1.1 --type syn --os-detect 2>/dev/null
```

### Paranoid slow scan (evades IDS)
```bash
sudo python3 stealth_scanner.py -t 192.168.1.1 --timing paranoid --randomize 2>/dev/null
```

### Subnet scan + HTML report
```bash
sudo python3 stealth_scanner.py -t 192.168.1.0/24 -p top100 -o report.html 2>/dev/null
```

---

## OS Detection Logic
1. **Port-based** (most accurate) — if Windows ports (135/139/445/3389) are open → Windows
2. **TTL fingerprint** — 128=Windows, 64=Linux, 255=BSD/macOS
3. **TCP Window size** — 8192=Windows, 29200=Linux, 65535=BSD
4. **Banner text** — SSH/service banners often name the OS directly

---

## All Options
| Flag | Description |
|---|---|
| `-t` | Target IP, hostname, or subnet CIDR |
| `-p` | Ports: `80`, `1-1024`, `22,80,443`, `top100`, `all` |
| `--type` | `connect` / `syn` / `udp` |
| `--stealth` | Enable all evasion techniques |
| `--decoys N` | Send N fake source IPs |
| `--fragment` | Split packets (bypasses shallow IDS) |
| `--spoof-port` | Use port 80/443/53 as source port |
| `--mimic-os` | Mimic `windows`/`linux`/`bsd` TTL |
| `--timing` | `paranoid` `sneaky` `polite` `normal` `aggressive` `insane` |
| `--randomize` | Randomize port scan order |
| `--os-detect` | Deep OS fingerprinting (TTL + window) |
| `--no-banner` | Disable banner grabbing |
| `-o file` | Save report (.html / .json / .txt) |
| `--timeout N` | Per-probe timeout in seconds |
| `-w N` | Max concurrent workers |

---

## Directory Structure
```
stealth_scanner/
├── stealth_scanner.py      # CLI entry point
├── requirements.txt
├── README.md
└── core/
    ├── scanner.py          # TCP/SYN/UDP scan engine + auto OS detection
    ├── stealth.py          # Evasion: decoys, fragmentation, TTL, timing
    ├── fingerprint.py      # OS + service fingerprinting
    └── reporter.py         # JSON / HTML / TXT reports
```
