"""
StealthScanner - OS & Service Fingerprinting
Uses TTL, TCP window size, and banner analysis to guess OS and service versions.
"""

import re
import socket
from typing import Dict, Optional, Tuple
from colorama import Fore, Style


# TTL → OS mapping (approximate)
TTL_OS_MAP = [
    (255, "Cisco IOS / BSD / Unix"),
    (128, "Windows"),
    (64,  "Linux / Android"),
    (60,  "Older Linux"),
    (32,  "Windows 95/98 (legacy)"),
]

# TCP Window Size → OS hints
WINDOW_OS_HINTS = {
    65535: "BSD/macOS",
    29200: "Linux (recent kernel)",
    8192:  "Windows",
    1024:  "Older Linux / embedded",
    4096:  "Solaris",
}

# Banner regex patterns for service identification
BANNER_PATTERNS = [
    (r"SSH-(\S+)",                    "SSH",        lambda m: m.group(0)),
    (r"220[- ].*FTP",                 "FTP",        lambda m: m.group(0)[:60]),
    (r"220[- ].*SMTP|Postfix|Exim",   "SMTP",       lambda m: m.group(0)[:60]),
    (r"HTTP/[\d.]+\s+\d+",            "HTTP",       lambda m: m.group(0)[:60]),
    (r"Server:\s*([^\r\n]+)",         "HTTP-Server",lambda m: m.group(1)[:60]),
    (r"MySQL",                        "MySQL",       lambda m: "MySQL DB"),
    (r"\$MYSQL_NATIVE_PASSWORD",      "MySQL",       lambda m: "MySQL DB"),
    (r"PostgreSQL",                   "PostgreSQL",  lambda m: "PostgreSQL DB"),
    (r"RFB \d+",                      "VNC",         lambda m: m.group(0)),
    (r"Microsoft.*RDP|^\x03\x00",     "RDP",         lambda m: "Microsoft RDP"),
    (r"IMAP|imapd",                   "IMAP",        lambda m: m.group(0)[:40]),
    (r"^\+OK",                        "POP3",        lambda m: m.group(0)[:40]),
    (r"redis_version:(\S+)",          "Redis",       lambda m: f"Redis {m.group(1)}"),
    (r"mongod",                       "MongoDB",     lambda m: "MongoDB"),
    (r"Elasticsearch",                "ES",          lambda m: "Elasticsearch"),
]


class Fingerprinter:
    """
    Passive and active OS/service fingerprinting.
    """

    @staticmethod
    def ttl_os_guess(ttl: int) -> str:
        """Guess OS from TTL value received in a response packet."""
        for threshold, os_name in TTL_OS_MAP:
            if ttl <= threshold:
                return os_name
        return "Unknown"

    @staticmethod
    def window_os_guess(window: int) -> str:
        """Guess OS from TCP window size."""
        return WINDOW_OS_HINTS.get(window, f"Unknown (window={window})")

    @staticmethod
    def fingerprint_from_packet(pkt) -> Dict[str, str]:
        """
        Attempt OS fingerprinting from a scapy response packet.
        Returns dict with 'os', 'ttl', 'window', 'flags'.
        """
        result = {"os": "Unknown", "ttl": "?", "window": "?", "flags": "?"}
        try:
            from scapy.all import IP, TCP
            if pkt.haslayer(IP):
                ttl = pkt[IP].ttl
                result["ttl"] = str(ttl)
                result["os"] = Fingerprinter.ttl_os_guess(ttl)
            if pkt.haslayer(TCP):
                win = pkt[TCP].window
                result["window"] = str(win)
                os_win = Fingerprinter.window_os_guess(win)
                if result["os"] == "Unknown":
                    result["os"] = os_win
                else:
                    result["os"] += f" / {os_win}"
                result["flags"] = str(pkt[TCP].flags)
        except Exception:
            pass
        return result

    @staticmethod
    def identify_service_from_banner(banner: str) -> Tuple[str, str]:
        """
        Parse a service banner and return (service_name, version_info).
        """
        if not banner:
            return ("unknown", "")
        for pattern, service, extractor in BANNER_PATTERNS:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                try:
                    detail = extractor(m)
                except Exception:
                    detail = service
                return (service, detail)
        return ("unknown", banner[:60])

    @staticmethod
    def active_os_probe(target: str, timeout: float = 2.0) -> Dict[str, str]:
        """
        Try to fingerprint the target OS by sending a crafted packet
        and analysing the response (TTL + window size).
        Requires scapy + root.
        """
        result = {"os": "Unknown", "ttl": "?", "window": "?"}
        try:
            from scapy.all import IP, TCP, sr1, conf
            conf.verb = 0
            pkt = IP(dst=target) / TCP(dport=80, flags="S")
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp:
                result = Fingerprinter.fingerprint_from_packet(resp)
                # Send RST to clean up
                from scapy.all import send
                send(IP(dst=target) / TCP(dport=80, flags="R"), verbose=0)
        except ImportError:
            result["os"] = "scapy not available"
        except PermissionError:
            result["os"] = "root required"
        except Exception:
            pass
        return result

    @staticmethod
    def print_os_result(result: Dict[str, str], target: str):
        print(f"\n{Fore.CYAN}[OS Fingerprint] {target}{Style.RESET_ALL}")
        print(f"  ├─ OS Guess : {Fore.GREEN}{result.get('os', 'Unknown')}{Style.RESET_ALL}")
        print(f"  ├─ TTL     : {result.get('ttl', '?')}")
        print(f"  └─ Window  : {result.get('window', '?')}")
