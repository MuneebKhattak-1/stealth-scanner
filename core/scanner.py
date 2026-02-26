"""
StealthScanner - Core Scanning Engine
Handles TCP SYN, UDP, and connect scans with evasion-aware logic.
"""

import socket
import random
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple
from tqdm import tqdm
from colorama import Fore, Style, init

init(autoreset=True)

# Well-known port → service name mapping
SERVICE_MAP = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmp-trap", 179: "bgp", 194: "irc", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 514: "syslog", 515: "printer", 543: "klogin",
    544: "kshell", 587: "smtp-sub", 631: "ipp", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1080: "socks", 1194: "openvpn", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 2082: "cpanel",
    2083: "cpanel-ssl", 2222: "ssh-alt", 3128: "squid-proxy",
    3306: "mysql", 3389: "rdp", 4444: "metasploit", 5432: "postgresql",
    5900: "vnc", 5985: "winrm-http", 5986: "winrm-https",
    6379: "redis", 6667: "irc", 7000: "cassandra", 8080: "http-alt",
    8443: "https-alt", 8888: "jupyter", 9200: "elasticsearch",
    27017: "mongodb", 27018: "mongodb-shard", 5601: "kibana",
}


class ScanResult:
    """Holds the result of a single port scan."""
    def __init__(self, host: str, port: int, state: str, service: str = "", banner: str = ""):
        self.host = host
        self.port = port
        self.state = state      # open / closed / filtered
        self.service = service
        self.banner = banner

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
        }

    def __repr__(self):
        color = Fore.GREEN if self.state == "open" else (Fore.YELLOW if self.state == "filtered" else Fore.RED)
        svc = f"  [{self.service}]" if self.service else ""
        banner = f"  \"{self.banner[:60]}\"" if self.banner else ""
        return f"{color}{self.host:<18}{str(self.port):<8}{self.state:<12}{svc}{banner}{Style.RESET_ALL}"


class CoreScanner:
    """
    Core scanning engine supporting:
    - TCP Connect scan (no root required)
    - TCP SYN scan (root required, uses scapy)
    - UDP scan
    - Banner grabbing
    - Slow/randomized scan modes
    """

    def __init__(
        self,
        targets: List[str],
        ports: List[int],
        timeout: float = 1.0,
        max_workers: int = 100,
        slow_mode: bool = False,
        randomize: bool = False,
        grab_banners: bool = True,
        scan_type: str = "connect",   # connect | syn | udp
        delay: float = 0.0,
    ):
        self.targets = targets
        self.ports = ports
        self.timeout = timeout
        self.max_workers = max_workers
        self.slow_mode = slow_mode
        self.randomize = randomize
        self.grab_banners = grab_banners
        self.scan_type = scan_type
        self.delay = delay if not slow_mode else random.uniform(0.5, 2.0)
        self.results: List[ScanResult] = []

    # ------------------------------------------------------------------ #
    #  Public interface                                                    #
    # ------------------------------------------------------------------ #

    def run(self) -> List[ScanResult]:
        """Run the scan and return all results."""
        port_list = self.ports.copy()
        if self.randomize:
            random.shuffle(port_list)

        tasks = [(host, port) for host in self.targets for port in port_list]
        if self.randomize:
            random.shuffle(tasks)

        print(f"\n{Fore.CYAN}[*] Starting {self.scan_type.upper()} scan on {len(self.targets)} host(s), "
              f"{len(port_list)} port(s) | Workers: {self.max_workers} | Timeout: {self.timeout}s{Style.RESET_ALL}\n")

        results = []
        with tqdm(total=len(tasks), desc="Scanning", unit="probe",
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]", colour="cyan") as pbar:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {executor.submit(self._probe, host, port): (host, port)
                           for host, port in tasks}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
                    pbar.update(1)

        self.results = sorted(results, key=lambda r: (r.host, r.port))
        return self.results

    # ------------------------------------------------------------------ #
    #  Probe dispatchers                                                   #
    # ------------------------------------------------------------------ #

    def _probe(self, host: str, port: int) -> Optional[ScanResult]:
        if self.slow_mode or self.delay:
            time.sleep(random.uniform(self.delay * 0.5, self.delay * 1.5))

        if self.scan_type == "syn":
            return self._syn_scan(host, port)
        elif self.scan_type == "udp":
            return self._udp_scan(host, port)
        else:
            return self._connect_scan(host, port)

    # ------------------------------------------------------------------ #
    #  TCP Connect scan                                                    #
    # ------------------------------------------------------------------ #

    def _connect_scan(self, host: str, port: int) -> Optional[ScanResult]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((host, port))
                if result == 0:
                    service = SERVICE_MAP.get(port, "unknown")
                    banner = self._grab_banner(s, port) if self.grab_banners else ""
                    return ScanResult(host, port, "open", service, banner)
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        return None

    # ------------------------------------------------------------------ #
    #  TCP SYN scan (requires root + scapy)                               #
    # ------------------------------------------------------------------ #

    def _syn_scan(self, host: str, port: int) -> Optional[ScanResult]:
        try:
            from scapy.all import IP, TCP, sr1, conf
            conf.verb = 0  # silence scapy output

            pkt = IP(dst=host) / TCP(dport=port, flags="S",
                                     seq=random.randint(1000, 9000000),
                                     window=random.choice([1024, 8192, 65535, 29200]))
            resp = sr1(pkt, timeout=self.timeout, verbose=0)

            if resp is None:
                return ScanResult(host, port, "filtered", SERVICE_MAP.get(port, ""))
            if resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags == 0x12:  # SYN-ACK → open
                    # Send RST to close gracefully (stealth)
                    from scapy.all import send
                    send(IP(dst=host) / TCP(dport=port, flags="R"), verbose=0)
                    service = SERVICE_MAP.get(port, "unknown")
                    return ScanResult(host, port, "open", service)
                elif flags == 0x14:  # RST-ACK → closed
                    return None  # Skip closed ports silently
        except ImportError:
            print(f"{Fore.YELLOW}[!] Scapy not available. Falling back to connect scan.{Style.RESET_ALL}")
            return self._connect_scan(host, port)
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------ #
    #  UDP scan                                                            #
    # ------------------------------------------------------------------ #

    def _udp_scan(self, host: str, port: int) -> Optional[ScanResult]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(b"\x00" * 8, (host, port))
                try:
                    data, _ = s.recvfrom(1024)
                    return ScanResult(host, port, "open", SERVICE_MAP.get(port, "unknown"))
                except socket.timeout:
                    return ScanResult(host, port, "open|filtered", SERVICE_MAP.get(port, ""))
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------ #
    #  Banner grabbing                                                     #
    # ------------------------------------------------------------------ #

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Attempt to grab banner without sending suspicious probes."""
        try:
            sock.settimeout(2)
            # Send HTTP-like probe for web ports
            if port in (80, 8080, 8000, 8888, 443, 8443):
                sock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            else:
                sock.send(b"\r\n")
            banner = sock.recv(1024).decode(errors="ignore").strip()
            return banner[:120]
        except Exception:
            return ""

    # ------------------------------------------------------------------ #
    #  Utility                                                             #
    # ------------------------------------------------------------------ #

    def print_results(self):
        """Pretty-print open/filtered ports."""
        open_ports = [r for r in self.results if r.state in ("open", "open|filtered")]
        if not open_ports:
            print(f"{Fore.YELLOW}[!] No open ports found.{Style.RESET_ALL}")
            return
        print(f"\n{Fore.GREEN}{'HOST':<18}{'PORT':<8}{'STATE':<12}SERVICE / BANNER{Style.RESET_ALL}")
        print("─" * 70)
        for r in open_ports:
            print(r)
