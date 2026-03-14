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

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

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
    def __init__(self, host: str, port: int, state: str, service: str = "", banner: str = "", os_guess: str = ""):
        self.host = host
        self.port = port
        self.state = state      # open / closed / filtered
        self.service = service
        self.banner = banner
        self.os_guess = os_guess  # OS fingerprint from packet

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
            "os_guess": self.os_guess,
        }

    def __repr__(self):
        color = Fore.GREEN if self.state == "open" else (Fore.YELLOW if self.state == "filtered" else Fore.RED)
        svc = f"  [{self.service}]" if self.service else ""
        banner = f"  \"{self.banner[:40]}\"" if self.banner else ""
        os_str = f"  OS:{self.os_guess}" if self.os_guess else ""
        return f"{color}{self.host:<18}{str(self.port):<8}{self.state:<12}{svc}{banner}{Fore.CYAN}{os_str}{Style.RESET_ALL}"


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
            from scapy.all import IP, TCP, sr1, conf, send
            from core.fingerprint import Fingerprinter
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
                    # Extract OS info from the response packet
                    fp = Fingerprinter.fingerprint_from_packet(resp)
                    os_guess = fp.get("os", "")
                    # Send RST to close gracefully (stealth)
                    send(IP(dst=host) / TCP(dport=port, flags="R"), verbose=0)
                    service = SERVICE_MAP.get(port, "unknown")
                    return ScanResult(host, port, "open", service, os_guess=os_guess)
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
    #  Auto Discovery (ARP)                                                #
    # ------------------------------------------------------------------ #

    @staticmethod
    def arp_discovery(network: str, timeout: float = 2.0) -> List[Tuple[str, str]]:
        """
        Perform an ARP ping sweep on the given network.
        Returns a list of (IP, MAC) tuples.
        Requires root privileges and scapy.
        """
        try:
            from scapy.all import Ether, ARP, srp, conf
            conf.verb = 0
            # Create an ARP request packet
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            # Send and receive packets over Layer 2
            print(f"{Fore.CYAN}[*] Broadcasting ARP on {network}...{Style.RESET_ALL}")
            result = srp(packet, timeout=timeout, verbose=0)[0]

            clients = []
            for sent, received in result:
                clients.append((received.psrc, received.hwsrc))
            
            return clients
        except PermissionError:
            print(f"{Fore.RED}[!] ARP Discovery requires root privileges (sudo).{Style.RESET_ALL}")
        except ImportError:
            print(f"{Fore.RED}[!] ARP Discovery requires 'scapy' module.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] ARP Discovery failed: {e}{Style.RESET_ALL}")
        return []

    # ------------------------------------------------------------------ #
    #  Auto Discovery (ARP)                                                #
    # ------------------------------------------------------------------ #

    @staticmethod
    def get_local_subnet() -> str:
        """Attempt to detect the local machine's best physical IP and return its /24 subnet."""
        try:
            # 1. Fallback routing test (finds default gateway interface)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            routed_ip = s.getsockname()[0]
            s.close()
            
            # 2. Get all addresses on the machine
            host_name = socket.gethostname()
            _, _, ip_addresses = socket.gethostbyname_ex(host_name)
            
            # Add the routed IP to the pool if not present
            if routed_ip not in ip_addresses:
                ip_addresses.append(routed_ip)
                
            # Filter and rank the IPs
            best_ip = None
            highest_score = -1
            
            for ip in ip_addresses:
                if ip.startswith("127.") or ip.startswith("169.254."):
                    continue  # Skip loopback and APIPA
                    
                score = 0
                if ip.startswith("192.168."):
                    score = 100  # Highest priority to standard home LANs
                elif ip.startswith("172."):
                    # Check if in private 172.16.0.0/12 range
                    second_octet = int(ip.split(".")[1])
                    if 16 <= second_octet <= 31:
                        score = 80
                elif ip.startswith("10."):
                    score = 50   # 10.x.x.x is often VM NAT or VPN
                else:
                    score = 20   # Public or other
                    
                # If this IP is the one with internet access, give it a slight boost
                if ip == routed_ip:
                    score += 10
                    
                if score > highest_score:
                    highest_score = score
                    best_ip = ip
            
            if not best_ip:
                best_ip = routed_ip # absolute fallback
                
            # Calculate the /24 subnet 
            network = ipaddress.IPv4Interface(f"{best_ip}/24").network
            return str(network)
        except Exception:
            return ""

    @staticmethod
    def arp_discovery(network: str, timeout: float = 2.0) -> List[Tuple[str, str]]:
        """
        Perform an ARP ping sweep on the given network.
        Returns a list of (IP, MAC) tuples.
        Requires root privileges and scapy.
        """
        try:
            from scapy.all import Ether, ARP, srp, conf
            conf.verb = 0
            # Create an ARP request packet
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            # Send and receive packets over Layer 2
            print(f"{Fore.CYAN}[*] Broadcasting ARP on {network}...{Style.RESET_ALL}")
            result = srp(packet, timeout=timeout, verbose=0)[0]

            clients = []
            for sent, received in result:
                clients.append((received.psrc, received.hwsrc))
            
            return clients
        except PermissionError:
            print(f"{Fore.RED}[!] ARP Discovery requires root privileges (sudo).{Style.RESET_ALL}")
        except ImportError:
            print(f"{Fore.RED}[!] ARP Discovery requires 'scapy' module.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] ARP Discovery failed: {e}{Style.RESET_ALL}")
        return []

    # ------------------------------------------------------------------ #
    #  Utility                                                             #
    # ------------------------------------------------------------------ #

    def print_results(self):
        """Pretty-print open/filtered ports with OS info."""
        open_ports = [r for r in self.results if r.state in ("open", "open|filtered")]
        if not open_ports:
            print(f"{Fore.YELLOW}[!] No open ports found.{Style.RESET_ALL}")
            return

        # Build per-host open port sets and banners
        from core.fingerprint import Fingerprinter
        host_port_sets: dict = {}
        host_banners: dict = {}
        for r in open_ports:
            host_port_sets.setdefault(r.host, set()).add(r.port)
            if r.banner:
                host_banners.setdefault(r.host, []).append(r.banner)

        # Determine OS per host using comprehensive logic
        host_os: dict = {}
        
        # 1. First, check if packet fingerprinting set an OS guess
        for r in open_ports:
            if r.host not in host_os and r.os_guess and r.os_guess != "Unknown":
                host_os[r.host] = r.os_guess

        # 2. Run active no-root detection (Ping TTL + SMB + Banners) for any missing or generic
        for host, ports in host_port_sets.items():
            current_os = host_os.get(host, "Unknown")
            banners = host_banners.get(host, [])
            
            # Ping TTL
            ttl = Fingerprinter.ping_ttl_probe(host, timeout=1.0)
            
            # SMB Negotiation (highly accurate for Windows)
            smb_os = None
            if 445 in ports or 139 in ports:
                smb_os = Fingerprinter.smb_os_discovery(host, timeout=3.0)
                
            if smb_os:
                host_os[host] = smb_os
                continue
                
            # Comprehensive Guess
            combined_os = Fingerprinter.comprehensive_os_guess(
                ttl=ttl,
                open_ports=ports,
                banners=banners
            )
            
            # Use specific comprehensive guess over generic port guess or packet guess if better
            if combined_os and combined_os != "Unknown":
                if current_os in ("Unknown", "Windows", "Linux"):
                    host_os[host] = combined_os
            elif current_os == "Unknown":
                port_guess = Fingerprinter.port_os_guess(ports)
                if port_guess:
                    host_os[host] = port_guess

        # Print OS summary per host
        if host_os:
            if HAS_TABULATE:
                print(f"\n{Fore.CYAN}[OS FINGERPRINT]{Style.RESET_ALL}")
                os_data = [[f"{Fore.CYAN}{host}{Style.RESET_ALL}", f"{Fore.GREEN}{os_name}{Style.RESET_ALL}"] for host, os_name in host_os.items()]
                print(tabulate(os_data, headers=["HOST", "OS GUESS"], tablefmt="plain"))
            else:
                print(f"\n{Fore.CYAN}{'HOST':<18} OS FINGERPRINT{Style.RESET_ALL}")
                print("─" * 50)
                for host, os_name in host_os.items():
                    print(f"{Fore.CYAN}{host:<18} {Fore.GREEN}{os_name}{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}[PORT SCAN RESULTS]{Style.RESET_ALL}")
        
        if HAS_TABULATE:
            table_data = []
            for r in open_ports:
                color = Fore.GREEN if r.state == "open" else Fore.YELLOW
                svc = f"[{r.service}]" if r.service else ""
                banner = f'"{r.banner[:40]}"' if r.banner else "-"
                table_data.append([
                    f"{color}{r.host}{Style.RESET_ALL}",
                    f"{str(r.port)}",
                    f"{color}{r.state}{Style.RESET_ALL}",
                    f"{svc}",
                    f"{banner}"
                ])
            print(tabulate(table_data, headers=["HOST", "PORT", "STATE", "SERVICE", "BANNER"], tablefmt="plain"))
        else:
            print(f"{Fore.GREEN}{'HOST':<18}{'PORT':<8}{'STATE':<12}{'SERVICE':<16}BANNER{Style.RESET_ALL}")
            print("─" * 80)
            for r in open_ports:
                color = Fore.GREEN if r.state == "open" else Fore.YELLOW
                svc = f"[{r.service}]" if r.service else ""
                banner = f'"{r.banner[:40]}"' if r.banner else ""
                print(f"{color}{r.host:<18}{str(r.port):<8}{r.state:<12}{svc:<16}{banner}{Style.RESET_ALL}")

    @staticmethod
    def print_discovery_results(clients: List[Tuple[str, str]]):
        """Pretty-print ARP discovery results using ASCII tables."""
        if not clients:
            return
            
        print(f"\n{Fore.GREEN}[+] Automatic Discovery Results:{Style.RESET_ALL}")
        if HAS_TABULATE:
            print(tabulate(clients, headers=["IP Address", "MAC Address"], tablefmt="fancy_grid"))
        else:
            print(f"{'IP Address':<18} {'MAC Address'}")
            print("─" * 36)
            for ip, mac in clients:
                print(f"{ip:<18} {mac}")

