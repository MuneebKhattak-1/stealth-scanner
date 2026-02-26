"""
StealthScanner - Evasion & Stealth Techniques
Implements decoy scanning, packet fragmentation, TTL manipulation,
source port spoofing, and timing evasion.
"""

import random
import time
import socket
from typing import List, Optional
from colorama import Fore, Style


class StealthEngine:
    """
    Provides evasion capabilities:
    - IP decoy injection (spoof additional source IPs alongside real scan)
    - Packet fragmentation (split IP packets to bypass shallow IDS rules)
    - TTL manipulation (mimic different OS hop counts)
    - Source port spoofing (mimic known benign services)
    - Timing jitter (irregular inter-packet delays to avoid rate-based detection)
    - Idle/Zombie scan support
    """

    # Source ports that look like legitimate traffic
    LEGIT_SOURCE_PORTS = [80, 443, 53, 123, 67, 68, 20, 21]

    # TTL values associated with common OS fingerprints
    OS_TTL = {
        "windows": 128,
        "linux":   64,
        "bsd":     255,
        "cisco":   255,
        "random":  None,
    }

    def __init__(
        self,
        num_decoys: int = 0,
        fragment: bool = False,
        spoof_source_port: bool = False,
        mimic_os: str = "linux",
        timing_jitter: bool = True,
        min_delay: float = 0.0,
        max_delay: float = 0.05,
    ):
        self.num_decoys = num_decoys
        self.fragment = fragment
        self.spoof_source_port = spoof_source_port
        self.mimic_os = mimic_os
        self.timing_jitter = timing_jitter
        self.min_delay = min_delay
        self.max_delay = max_delay

    # ------------------------------------------------------------------ #
    #  Decoy generation                                                   #
    # ------------------------------------------------------------------ #

    def generate_decoys(self, real_ip: str) -> List[str]:
        """
        Generate a list of decoy IPs mixed with the real scanner IP.
        These are injected into scapy packets so IDS logs see many sources.
        """
        decoys = []
        real_pos = random.randint(0, self.num_decoys)

        for i in range(self.num_decoys + 1):
            if i == real_pos:
                decoys.append(real_ip)
            else:
                # Generate a random routable-looking IP
                decoys.append(self._random_routable_ip())

        return decoys

    def _random_routable_ip(self) -> str:
        """Generate a random public-looking IP (avoids RFC1918 private ranges)."""
        while True:
            a = random.randint(1, 254)
            b = random.randint(0, 254)
            c = random.randint(0, 254)
            d = random.randint(1, 254)
            ip = f"{a}.{b}.{c}.{d}"
            # Exclude private, loopback, link-local ranges
            if not (a == 10 or a == 127 or a == 0
                    or (a == 172 and 16 <= b <= 31)
                    or (a == 192 and b == 168)
                    or (a == 169 and b == 254)):
                return ip

    # ------------------------------------------------------------------ #
    #  SYN scan with evasion (requires scapy + root)                      #
    # ------------------------------------------------------------------ #

    def syn_scan_with_evasion(self, target: str, port: int, timeout: float = 1.0) -> Optional[str]:
        """
        Perform a SYN probe with all enabled evasion techniques applied.
        Returns: 'open', 'filtered', or None (closed/error).
        """
        try:
            from scapy.all import IP, TCP, sr1, conf, send
            conf.verb = 0

            ttl = self._get_ttl()
            sport = self._get_source_port()

            ip_layer = IP(dst=target, ttl=ttl)
            tcp_layer = TCP(
                sport=sport,
                dport=port,
                flags="S",
                seq=random.randint(1000, 9000000),
                window=random.choice([1024, 8192, 29200, 65535]),
                options=[("Timestamp", (random.randint(100000, 9999999), 0))]
            )
            pkt = ip_layer / tcp_layer

            if self.fragment:
                pkt = self._fragment_packet(pkt)

            if self.timing_jitter:
                time.sleep(random.uniform(self.min_delay, self.max_delay))

            if self.num_decoys > 0:
                self._send_decoys(target, port, sport, ttl)

            resp = sr1(pkt, timeout=timeout, verbose=0)

            if resp is None:
                return "filtered"
            if resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags == 0x12:  # SYN-ACK
                    send(IP(dst=target) / TCP(dport=port, sport=sport, flags="R"), verbose=0)
                    return "open"
                elif flags == 0x14:  # RST-ACK
                    return "closed"

        except ImportError:
            print(f"{Fore.YELLOW}[!] Scapy not installed. Run: pip install scapy{Style.RESET_ALL}")
        except PermissionError:
            print(f"{Fore.RED}[!] SYN scan requires root privileges. Run with sudo.{Style.RESET_ALL}")
        except Exception as e:
            pass
        return None

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _get_ttl(self) -> int:
        ttl = self.OS_TTL.get(self.mimic_os, 64)
        if ttl is None:
            ttl = random.randint(48, 128)
        # Add small jitter to avoid identical TTL fingerprint
        return ttl + random.randint(-2, 2)

    def _get_source_port(self) -> int:
        if self.spoof_source_port:
            return random.choice(self.LEGIT_SOURCE_PORTS)
        return random.randint(1024, 65535)

    def _fragment_packet(self, pkt):
        """Fragment the IP packet into small pieces."""
        from scapy.all import fragment
        return fragment(pkt, fragsize=8)  # 8-byte fragments bypass many IDS rules

    def _send_decoys(self, target: str, port: int, sport: int, ttl: int):
        """
        Send SYN packets from decoy IPs to confuse IDS logs.
        Note: requires network allows spoofed source IPs (many ISPs block).
        """
        try:
            from scapy.all import IP, TCP, send
            real_ip = self._get_local_ip()
            decoys = self.generate_decoys(real_ip)

            for decoy_ip in decoys:
                if decoy_ip == real_ip:
                    continue  # real packet sent separately
                send(IP(src=decoy_ip, dst=target, ttl=ttl) /
                     TCP(sport=sport, dport=port, flags="S"), verbose=0)
        except Exception:
            pass

    @staticmethod
    def _get_local_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"


class TimingProfile:
    """
    Pre-defined timing profiles (mimics nmap -T0 through -T5).
    """
    PROFILES = {
        "paranoid":   {"delay": 5.0,  "max_delay": 10.0, "workers": 1},
        "sneaky":     {"delay": 0.5,  "max_delay": 3.0,  "workers": 5},
        "polite":     {"delay": 0.1,  "max_delay": 0.5,  "workers": 10},
        "normal":     {"delay": 0.01, "max_delay": 0.05, "workers": 50},
        "aggressive": {"delay": 0.0,  "max_delay": 0.01, "workers": 200},
        "insane":     {"delay": 0.0,  "max_delay": 0.0,  "workers": 500},
    }

    @classmethod
    def get(cls, name: str) -> dict:
        return cls.PROFILES.get(name, cls.PROFILES["normal"])
