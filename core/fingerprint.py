"""
StealthScanner - OS & Service Fingerprinting
Uses TTL, TCP window size, and banner analysis to guess OS and service versions.
"""

import re
import random
import socket
from typing import Dict, Optional, Tuple
from colorama import Fore, Style



# TTL → OS mapping: (exact_default_ttl, os_name)
TTL_OS_MAP = [
    (128, "Windows"),
    (64,  "Linux / Android"),
    (255, "BSD / macOS / Cisco"),
    (60,  "Older Linux"),
    (32,  "Windows 95/98 (legacy)"),
]

# TCP Window Size → OS hints (generic fallback)
WINDOW_OS_HINTS = {
    65535: "BSD/macOS",
    29200: "Linux (recent kernel)",
    8192:  "Windows",
    1024:  "Older Linux / embedded",
    4096:  "Solaris",
}

# ─── Detailed TTL + Window → OS Version mapping ──────────────────────────
# When we have BOTH TTL and Window, use this combined table for
# much more specific OS version detection.
TTL_WINDOW_OS_MAP = [
    # Windows versions
    (128, 65535, "Windows 10 / 11 / Server 2016+"),
    (128, 64240, "Windows 10 (v1703+) / Windows 11"),
    (128, 8192,  "Windows 7 / Server 2008 R2"),
    (128, 16384, "Windows XP SP3 / Server 2003"),
    (128, 17520, "Windows Vista / Server 2008"),
    (128, 64512, "Windows 10 (early builds)"),
    (128, 32768, "Windows XP SP1-SP2"),
    (128, 5840,  "Windows Server 2003 SP2"),
    (128, 5720,  "Windows Server 2003 SP1"),
    (128, 64000, "Windows 10 / Server 2019"),
    (128, 32120, "Windows Vista SP2"),
    (128, 62780, "Windows 11 (22H2+)"),

    # Linux versions
    (64,  29200, "Linux 3.x / 4.x (Ubuntu 14-18 / CentOS 7)"),
    (64,  26883, "Linux 5.x (Ubuntu 20+ / CentOS 8+)"),
    (64,  64240, "Linux 5.x / 6.x (Ubuntu 22+ / Fedora 36+)"),
    (64,  65535, "Linux 2.6.x (legacy) / FreeBSD"),
    (64,  5840,  "Linux 2.6 (Debian 6 / CentOS 5)"),
    (64,  14600, "Linux 3.x (Debian 7 / Ubuntu 12)"),
    (64,  14480, "Linux 3.x (RHEL 6)"),
    (64,  28960, "Linux 4.x (Debian 9)"),
    (64,  32120, "Linux 5.x (Debian 11 / Kali)"),
    (64,  65160, "Linux 6.x (latest kernels)"),
    (64,  1024,  "Linux embedded / IoT device"),

    # BSD / macOS
    (64,  65535, "FreeBSD / macOS"),
    (255, 65535, "OpenBSD / Cisco IOS / Solaris"),
    (255, 16384, "Cisco IOS 12.x"),
    (255, 4128,  "Cisco IOS 15.x"),
    (255, 8192,  "Cisco NX-OS"),

    # Solaris / AIX / Exotic
    (64,  49232, "macOS 10.14+ (Mojave/Catalina/Ventura)"),
    (64,  4096,  "Solaris 10 / 11"),
    (60,  16384, "AIX 5.x / 6.x"),
    (60,  65535, "AIX 7.x"),
]

# Window size ranges → version hints when exact match fails
WINDOW_RANGE_OS = [
    # TTL ~128 (Windows family)
    (120, 135, 60000, 65536, "Windows 10 / 11"),
    (120, 135, 8000,  8300,  "Windows 7 / Server 2008"),
    (120, 135, 16000, 17600, "Windows XP / Server 2003"),
    (120, 135, 30000, 33000, "Windows XP SP1-SP2"),
    (120, 135, 5500,  6000,  "Windows Server 2003"),
    # TTL ~64 (Linux family)
    (58,  68,  28000, 30000, "Linux 3.x / 4.x"),
    (58,  68,  26000, 28000, "Linux 5.x (modern)"),
    (58,  68,  60000, 65536, "Linux 5.x / 6.x (latest)"),
    (58,  68,  14000, 15000, "Linux 3.x (older)"),
    (58,  68,  5000,  6000,  "Linux 2.6.x (legacy)"),
    (58,  68,  48000, 50000, "macOS 10.14+"),
]

# Port-based OS signatures (most reliable method)
PORT_OS_MAP = {
    # Windows-specific ports
    frozenset({135}):          "Windows",
    frozenset({139}):          "Windows",
    frozenset({445}):          "Windows",
    frozenset({3389}):         "Windows (RDP enabled)",
    frozenset({5985}):         "Windows (WinRM enabled)",
    frozenset({135, 139}):     "Windows",
    frozenset({135, 445}):     "Windows",
    frozenset({135, 139, 445}): "Windows",
    # Linux-specific ports
    frozenset({22, 111}):      "Linux",
    frozenset({2049}):         "Linux (NFS)",
    # macOS specific
    frozenset({548}):          "macOS (AFP)",
    frozenset({5900, 22}):     "macOS / Linux",
}

# Banner → OS version regex patterns
BANNER_OS_PATTERNS = [
    # SSH banners → very reliable for OS version
    (r"OpenSSH_[\d.]+\s+Ubuntu",                      "Ubuntu Linux"),
    (r"OpenSSH_9\.\d.*Ubuntu-.*ubuntu",                "Ubuntu 24.x+"),
    (r"OpenSSH_8\.9.*Ubuntu",                          "Ubuntu 22.04 LTS"),
    (r"OpenSSH_8\.4.*Ubuntu",                          "Ubuntu 20.04 LTS"),
    (r"OpenSSH_8\.2.*Ubuntu",                          "Ubuntu 20.04 LTS"),
    (r"OpenSSH_7\.6.*Ubuntu",                          "Ubuntu 18.04 LTS"),
    (r"OpenSSH_7\.2.*Ubuntu",                          "Ubuntu 16.04 LTS"),
    (r"OpenSSH_6\.6.*Ubuntu",                          "Ubuntu 14.04 LTS"),
    (r"OpenSSH_[\d.]+\s+Debian",                       "Debian Linux"),
    (r"OpenSSH_9\.\d.*Debian",                         "Debian 12 (Bookworm)"),
    (r"OpenSSH_8\.4.*Debian",                          "Debian 11 (Bullseye)"),
    (r"OpenSSH_7\.9.*Debian",                          "Debian 10 (Buster)"),
    (r"OpenSSH_7\.4.*Debian",                          "Debian 9 (Stretch)"),
    (r"OpenSSH_[\d.]+.*Fedora",                        "Fedora Linux"),
    (r"OpenSSH_[\d.]+.*el9",                           "RHEL 9 / CentOS Stream 9"),
    (r"OpenSSH_[\d.]+.*el8",                           "RHEL 8 / CentOS 8 / Rocky 8"),
    (r"OpenSSH_[\d.]+.*el7",                           "RHEL 7 / CentOS 7"),
    (r"OpenSSH_[\d.]+.*el6",                           "RHEL 6 / CentOS 6"),
    (r"OpenSSH_[\d.]+.*FreeBSD",                       "FreeBSD"),
    (r"OpenSSH_[\d.]+\s*$",                            "Linux / Unix"),  # generic OpenSSH
    # Windows SSH
    (r"OpenSSH.*Windows",                              "Windows 10+ (OpenSSH)"),
    (r"SSH.*Windows",                                  "Windows (SSH enabled)"),
    # Microsoft services
    (r"Microsoft FTP Service",                         "Windows Server (IIS FTP)"),
    (r"Microsoft-IIS/([\d.]+)",                        None),  # handled specially
    (r"Microsoft ESMTP MAIL",                          "Windows Server (Exchange)"),
    (r"Microsoft-HTTPAPI/([\d.]+)",                    "Windows Server (HTTP.sys)"),
    # Apache → OS hint
    (r"Apache/[\d.]+ \(Ubuntu\)",                      "Ubuntu Linux (Apache)"),
    (r"Apache/[\d.]+ \(Debian\)",                      "Debian Linux (Apache)"),
    (r"Apache/[\d.]+ \(CentOS\)",                      "CentOS Linux (Apache)"),
    (r"Apache/[\d.]+ \(Red Hat\)",                     "RHEL (Apache)"),
    (r"Apache/[\d.]+ \(Fedora\)",                      "Fedora Linux (Apache)"),
    (r"Apache/[\d.]+ \(Win32\)",                       "Windows (Apache)"),
    (r"Apache/[\d.]+ \(Win64\)",                       "Windows (Apache)"),
    (r"Apache/[\d.]+ \(FreeBSD\)",                     "FreeBSD (Apache)"),
    # nginx → usually Linux but can be anywhere
    (r"nginx/[\d.]+\s+\(Ubuntu\)",                     "Ubuntu Linux (nginx)"),
    # Samba → Linux
    (r"Samba",                                         "Linux (Samba)"),
    # Pure-FTPd
    (r"Pure-FTPd",                                     "Linux (Pure-FTPd)"),
    (r"vsFTPd ([\d.]+)",                               "Linux (vsftpd)"),
    (r"ProFTPD",                                       "Linux (ProFTPD)"),
    # Postfix / Exim / Sendmail
    (r"Postfix",                                       "Linux (Postfix SMTP)"),
    (r"Exim",                                          "Linux (Exim SMTP)"),
]

# IIS version → Windows version mapping
IIS_VERSION_MAP = {
    "10.0": "Windows Server 2016/2019/2022",
    "8.5":  "Windows Server 2012 R2",
    "8.0":  "Windows Server 2012",
    "7.5":  "Windows 7 / Server 2008 R2",
    "7.0":  "Windows Vista / Server 2008",
    "6.0":  "Windows Server 2003",
    "5.1":  "Windows XP (IIS)",
    "5.0":  "Windows 2000 Server",
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
        """Guess OS from TTL value — finds closest default TTL match."""
        best_match = "Unknown"
        best_diff = 999
        for default_ttl, os_name in TTL_OS_MAP:
            diff = abs(default_ttl - ttl)
            if diff < best_diff:
                best_diff = diff
                best_match = os_name
        return best_match

    @staticmethod
    def window_os_guess(window: int) -> str:
        """Guess OS from TCP window size."""
        return WINDOW_OS_HINTS.get(window, "")

    @staticmethod
    def detailed_os_guess(ttl: int, window: int) -> str:
        """
        Guess specific OS version from TTL + Window size combination.
        Returns a detailed version string or empty string if no confident match.
        """
        # Try exact TTL + Window match first
        for map_ttl, map_win, os_version in TTL_WINDOW_OS_MAP:
            if ttl == map_ttl and window == map_win:
                return os_version

        # Try close TTL match (within hop range) + exact window
        for map_ttl, map_win, os_version in TTL_WINDOW_OS_MAP:
            if abs(ttl - map_ttl) <= 5 and window == map_win:
                return os_version

        # Try range-based matching
        for ttl_lo, ttl_hi, win_lo, win_hi, os_version in WINDOW_RANGE_OS:
            if ttl_lo <= ttl <= ttl_hi and win_lo <= window <= win_hi:
                return os_version

        return ""

    @staticmethod
    def banner_os_guess(banner: str) -> str:
        """
        Extract OS version information from service banners.
        Returns a specific OS version string or empty string.
        """
        if not banner:
            return ""

        for pattern, os_version in BANNER_OS_PATTERNS:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                # Special handling for IIS version → Windows mapping
                if os_version is None and "IIS" in pattern:
                    iis_ver = m.group(1)
                    for ver_prefix, win_ver in IIS_VERSION_MAP.items():
                        if iis_ver.startswith(ver_prefix):
                            return win_ver
                    return f"Windows Server (IIS {iis_ver})"
                if os_version:
                    return os_version

        return ""

    @staticmethod
    def port_os_guess(open_ports: set) -> str:
        """
        Guess OS from set of open ports — most reliable method.
        Returns OS string if confident match found, else empty string.
        """
        for port_set, os_name in PORT_OS_MAP.items():
            if port_set.issubset(open_ports):
                return os_name
        return ""

    @staticmethod
    def comprehensive_os_guess(ttl: int = -1, window: int = -1,
                                open_ports: set = None, banners: list = None) -> str:
        """
        Combined OS fingerprinting using all available data.
        Priority: banner version > TTL+Window detail > port-based > TTL generic.
        Returns the most specific OS version string possible.
        """
        guesses = []

        # 1. Banner-based (most specific)
        if banners:
            for banner in banners:
                banner_os = Fingerprinter.banner_os_guess(banner)
                if banner_os:
                    guesses.append(("banner", banner_os))

        # 2. TTL + Window combined (very specific)
        if ttl > 0 and window > 0:
            detailed = Fingerprinter.detailed_os_guess(ttl, window)
            if detailed:
                guesses.append(("ttl_window", detailed))

        # 3. Port-based (reliable for OS family)
        if open_ports:
            port_os = Fingerprinter.port_os_guess(open_ports)
            if port_os:
                guesses.append(("port", port_os))

        # 4. TTL generic (fallback)
        if ttl > 0:
            ttl_os = Fingerprinter.ttl_os_guess(ttl)
            if ttl_os and ttl_os != "Unknown":
                guesses.append(("ttl", ttl_os))

        if not guesses:
            return "Unknown"

        # Return the most specific guess (banner > ttl_window > port > ttl)
        priority = {"banner": 0, "ttl_window": 1, "port": 2, "ttl": 3}
        guesses.sort(key=lambda g: priority.get(g[0], 99))
        return guesses[0][1]

    @staticmethod
    def fingerprint_from_packet(pkt) -> Dict[str, str]:
        """
        Attempt OS fingerprinting from a scapy response packet.
        Returns dict with 'os', 'ttl', 'window', 'flags'.
        Uses TTL+Window combined lookup for detailed version info.
        """
        result = {"os": "Unknown", "ttl": "?", "window": "?", "flags": "?"}
        try:
            from scapy.all import IP, TCP
            ttl = -1
            win = -1
            if pkt.haslayer(IP):
                ttl = pkt[IP].ttl
                result["ttl"] = str(ttl)
            if pkt.haslayer(TCP):
                win = pkt[TCP].window
                result["window"] = str(win)
                result["flags"] = str(pkt[TCP].flags)

            # Use detailed combined guess first, fall back to generic
            if ttl > 0 and win > 0:
                detailed = Fingerprinter.detailed_os_guess(ttl, win)
                if detailed:
                    result["os"] = detailed
                else:
                    result["os"] = Fingerprinter.ttl_os_guess(ttl)
            elif ttl > 0:
                result["os"] = Fingerprinter.ttl_os_guess(ttl)
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
        """Probe port 80 for OS fingerprinting (legacy fallback)."""
        return Fingerprinter.active_os_probe_port(target, 80, timeout)

    @staticmethod
    def active_os_probe_port(target: str, port: int = 80, timeout: float = 2.0) -> Dict[str, str]:
        """
        Fingerprint OS by probing a SPECIFIC port (use a known-open port
        for best results, e.g. 135 for Windows, 22 for Linux).
        Requires scapy + root.
        """
        result = {"os": "Unknown", "ttl": "?", "window": "?"}
        try:
            from scapy.all import IP, TCP, sr1, conf, send
            conf.verb = 0
            pkt = IP(dst=target) / TCP(dport=port, flags="S",
                                       seq=random.randint(1000, 9000000))
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp:
                result = Fingerprinter.fingerprint_from_packet(resp)
                send(IP(dst=target) / TCP(dport=port, flags="R"), verbose=0)
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
