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
        Returns dict with 'os', 'ttl', 'window', 'flags', 'method'.
        Uses TTL+Window combined lookup for detailed version info.
        """
        result = {"os": "Unknown", "ttl": "?", "window": "?", "flags": "?", "method": "packet"}
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
        Fingerprint OS by probing a SPECIFIC port.
        Tries scapy first (root), falls back to non-root methods.
        """
        result = {"os": "Unknown", "ttl": "?", "window": "?"}
        # Try scapy-based probe first (most accurate, requires root)
        try:
            from scapy.all import IP, TCP, sr1, conf, send
            conf.verb = 0
            pkt = IP(dst=target) / TCP(dport=port, flags="S",
                                       seq=random.randint(1000, 9000000))
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp:
                result = Fingerprinter.fingerprint_from_packet(resp)
                send(IP(dst=target) / TCP(dport=port, flags="R"), verbose=0)
                if result.get("os", "Unknown") != "Unknown":
                    return result
        except (ImportError, PermissionError, OSError):
            pass
        except Exception:
            pass

        # Fall back to non-root methods
        return Fingerprinter.noroot_os_probe(target, port, timeout)

    @staticmethod
    def noroot_os_probe(target: str, port: int = 80, timeout: float = 2.0) -> Dict[str, str]:
        """
        OS fingerprinting WITHOUT root privileges.
        Combines ping TTL + SMB negotiation + TCP window probing.
        """
        result = {"os": "Unknown", "ttl": "?", "window": "?", "method": "no-root"}

        # 1. Get TTL via ping (works without root on most systems)
        ttl = Fingerprinter.ping_ttl_probe(target, timeout)
        if ttl > 0:
            result["ttl"] = str(ttl)
            result["os"] = Fingerprinter.ttl_os_guess(ttl)

        # 2. If TTL is available, get detailed version (Window will be missing without root)
        if ttl > 0:
            result["os"] = Fingerprinter.ttl_os_guess(ttl)

        # 3. Try SMB negotiation for Windows version (port 445)
        smb_os = Fingerprinter.smb_os_discovery(target, timeout)
        if smb_os:
            result["os"] = smb_os
            result["method"] = "SMB"

        return result

    @staticmethod
    def ping_ttl_probe(target: str, timeout: float = 2.0) -> int:
        """
        Get TTL value from the target using ICMP ping.
        Works without root on most Linux/macOS systems.
        Returns TTL value or -1 on failure.
        """
        import subprocess
        import platform

        try:
            os_name = platform.system().lower()
            if os_name == "windows":
                cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), target]
            else:
                cmd = ["ping", "-c", "1", "-W", str(int(timeout)), target]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
            output = proc.stdout

            # Parse TTL from ping output
            # Linux:   "ttl=64"
            # Windows: "TTL=128"
            # macOS:   "ttl=64"
            ttl_match = re.search(r'ttl[=:](\d+)', output, re.IGNORECASE)
            if ttl_match:
                return int(ttl_match.group(1))
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass

        return -1



    @staticmethod
    def smb_os_discovery(target: str, timeout: float = 3.0) -> str:
        """
        Connect to port 445 and perform SMB2 Negotiate to extract
        the exact Windows version from the response.
        Works WITHOUT root privileges — just a regular TCP connection.
        Returns OS version string or empty string on failure.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, 445))

            # ─── SMB2 Negotiate Request ───────────────────────────────
            # NetBIOS Session header + SMB2 Negotiate packet
            # Length = Header(64) + Body(36) + Dialects(8) = 108 bytes
            smb2_negotiate = (
                # NetBIOS Session Service
                b'\x00'          # Message type: Session Message
                b'\x00\x00\x6c' # Length (108 bytes)
                # SMB2 Header
                b'\xfe\x53\x4d\x42'   # Protocol ID: 0xFE 'SMB'
                b'\x40\x00'           # Header length: 64
                b'\x00\x00'           # Credit charge: 0
                b'\x00\x00'           # Channel sequence
                b'\x00\x00'           # Reserved
                b'\x00\x00'           # Command: NEGOTIATE (0x0000)
                b'\x00\x00'           # Credits requested: 0
                b'\x00\x00\x00\x00'   # Flags
                b'\x00\x00\x00\x00'   # Next command: 0
                b'\x01\x00\x00\x00\x00\x00\x00\x00'  # Message ID: 1
                b'\x00\x00\x00\x00'   # Process ID
                b'\x00\x00\x00\x00'   # Tree ID
                b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Session ID
                b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Signature (8 bytes)
                b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Signature (8 bytes)
                # SMB2 Negotiate Request body
                b'\x24\x00'           # Structure size: 36
                b'\x04\x00'           # Dialect count: 4
                b'\x01\x00'           # Security mode
                b'\x00\x00'           # Reserved
                b'\x7f\x00\x00\x00'   # Capabilities (Supports DFS, Leasing, Large MTU, MultiChannel, PersistentHandles, DirectoryLeasing, Encryption)
                b'\x00\x00\x00\x00\x00\x00\x00\x00'   # Client GUID (8 bytes)
                b'\x00\x00\x00\x00\x00\x00\x00\x00'   # Client GUID (8 bytes)
                b'\x00\x00\x00\x00'   # Negotiate context offset
                b'\x00\x00'           # Negotiate context count
                b'\x00\x00'           # Reserved2
                b'\x02\x02'           # Dialect: SMB 2.0.2
                b'\x10\x02'           # Dialect: SMB 2.1
                b'\x00\x03'           # Dialect: SMB 3.0
                b'\x11\x03'           # Dialect: SMB 3.1.1
            )

            s.send(smb2_negotiate)
            response = s.recv(1024)
            s.close()

            if len(response) < 70:
                return ""

            # Check for SMB2 response signature
            # NetBIOS header is 4 bytes, then SMB2 header starts
            smb_offset = 4
            if response[smb_offset:smb_offset+4] != b'\xfe\x53\x4d\x42':
                # Maybe SMB1 response — try to parse NTLM info
                return Fingerprinter._parse_smb1_os(response)

            # SMB2 Negotiate Response — the header is 64 bytes
            # After header (offset 68), the negotiate response body starts
            body_offset = smb_offset + 64  # 68

            if len(response) < body_offset + 65:
                return ""

            # Negotiate response structure:
            # +0: StructureSize (2)  +2: SecurityMode (2)  +4: DialectRevision (2)
            # +6: NegotiateContextCount (2)  +8: ServerGuid (16)
            # +24: Capabilities (4)  +28: MaxTransactSize (4)
            # +32: MaxReadSize (4)  +36: MaxWriteSize (4)
            # +40: SystemTime (8)   +48: ServerStartTime (8)
            # +56: SecurityBufferOffset (2)  +58: SecurityBufferLength (2)

            dialect = int.from_bytes(response[body_offset+4:body_offset+6], 'little')

            # Try to extract NTLM info from the security buffer
            sec_offset_raw = int.from_bytes(response[body_offset+56:body_offset+58], 'little')
            sec_length = int.from_bytes(response[body_offset+58:body_offset+60], 'little')

            if sec_length > 0 and sec_offset_raw > 0:
                sec_offset = smb_offset + sec_offset_raw
                if len(response) >= sec_offset + sec_length:
                    sec_blob = response[sec_offset:sec_offset + sec_length]
                    ntlm_os = Fingerprinter._parse_ntlm_os_version(sec_blob)
                    if ntlm_os:
                        return ntlm_os

            # Fallback: dialect-based version guess
            dialect_map = {
                0x0311: "Windows 10+ / Server 2016+ (SMB 3.1.1)",
                0x0300: "Windows 8.1+ / Server 2012 R2+ (SMB 3.0)",
                0x0210: "Windows 7+ / Server 2008 R2+ (SMB 2.1)",
                0x0202: "Windows Vista+ / Server 2008+ (SMB 2.0.2)",
            }
            return dialect_map.get(dialect, "")

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        except Exception:
            pass
        return ""

    @staticmethod
    def _parse_ntlm_os_version(sec_blob: bytes) -> str:
        """Parse NTLM security blob for OS version info."""
        try:
            # Look for NTLMSSP signature in the blob
            ntlm_pos = sec_blob.find(b'NTLMSSP\x00')
            if ntlm_pos < 0:
                return ""

            ntlm_data = sec_blob[ntlm_pos:]

            # NTLMSSP Challenge message (type 2)
            # Version info is at offset 48 (8 bytes): Major, Minor, Build, Reserved, NTLMRevision
            if len(ntlm_data) < 56:
                return ""

            msg_type = int.from_bytes(ntlm_data[8:12], 'little')
            if msg_type != 2:  # Not a Challenge message
                return ""

            # Check if version info is present (flag bit 25)
            flags = int.from_bytes(ntlm_data[20:24], 'little')
            if not (flags & 0x02000000):  # NTLMSSP_NEGOTIATE_VERSION
                return ""

            # Version is at offset 48
            major = ntlm_data[48]
            minor = ntlm_data[49]
            build = int.from_bytes(ntlm_data[50:52], 'little')

            # Map Windows version numbers to names
            version_map = {
                (10, 0): "Windows 10 / 11 / Server 2016-2022",
                (6, 3):  "Windows 8.1 / Server 2012 R2",
                (6, 2):  "Windows 8 / Server 2012",
                (6, 1):  "Windows 7 / Server 2008 R2",
                (6, 0):  "Windows Vista / Server 2008",
                (5, 2):  "Windows XP x64 / Server 2003",
                (5, 1):  "Windows XP",
                (5, 0):  "Windows 2000",
            }

            os_name = version_map.get((major, minor), f"Windows NT {major}.{minor}")

            # Use build number to differentiate Win 10 vs 11
            if major == 10 and minor == 0:
                if build >= 22000:
                    os_name = f"Windows 11 (Build {build})"
                elif build >= 20348:
                    os_name = f"Windows Server 2022 (Build {build})"
                elif build >= 17763:
                    os_name = f"Windows 10 / Server 2019 (Build {build})"
                elif build >= 14393:
                    os_name = f"Windows 10 / Server 2016 (Build {build})"
                else:
                    os_name = f"Windows 10 (Build {build})"
            else:
                os_name = f"{os_name} (Build {build})"

            return os_name

        except Exception:
            pass
        return ""

    @staticmethod
    def _parse_smb1_os(response: bytes) -> str:
        """Try to extract OS string from SMB1 negotiate response."""
        try:
            # Look for readable OS strings in the response
            text = response.decode('utf-16-le', errors='ignore')
            # Common patterns in SMB1 responses
            for pattern in [r'Windows\s+[\d.]+[\w\s]*', r'Windows\s+Server\s+\d+[\w\s]*',
                           r'Windows\s+\d+[\w\s]*']:
                m = re.search(pattern, text)
                if m:
                    return m.group(0).strip()[:50]
        except Exception:
            pass
        return ""

    @staticmethod
    def print_os_result(result: Dict[str, str], target: str):
        print(f"\n{Fore.CYAN}[OS Fingerprint] {target}{Style.RESET_ALL}")
        print(f"  ├─ OS Guess : {Fore.GREEN}{result.get('os', 'Unknown')}{Style.RESET_ALL}")
        print(f"  ├─ TTL     : {result.get('ttl', '?')}")
        print(f"  └─ Window  : {result.get('window', '?')}")

