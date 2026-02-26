"""
StealthScan - Main Entry Point
A Python-based stealth network scanner for Kali Linux.

LEGAL: Use ONLY on systems you own or have written permission to test.
Unauthorized scanning is illegal.
"""

import sys
import argparse
import ipaddress
import time
import socket
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}
  ██████╗████████╗███████╗ █████╗ ██╗  ████████╗██╗  ██╗
 ██╔════╝╚══██╔══╝██╔════╝██╔══██╗██║  ╚══██╔══╝██║  ██║
 ╚█████╗    ██║   █████╗  ███████║██║     ██║   ███████║
  ╚═══██╗   ██║   ██╔══╝  ██╔══██║██║     ██║   ██╔══██║
 ██████╔╝   ██║   ███████╗██║  ██║███████╗██║   ██║  ██║
 ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝  ╚═╝
{Style.RESET_ALL}
 {Fore.GREEN}StealthScan v1.1  |  Python Network Reconnaissance Tool{Style.RESET_ALL}
 {Fore.RED}[!] For authorized penetration testing ONLY{Style.RESET_ALL}
"""


def parse_ports(port_str: str):
    """Parse port specification: '80', '1-1024', '22,80,443', 'top100'."""
    TOP_100 = [
        21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123,
        135, 137, 138, 139, 143, 161, 162, 179, 194, 389, 443, 445,
        465, 500, 514, 515, 587, 631, 636, 993, 995, 1080, 1194, 1433,
        1521, 1723, 2049, 2082, 2083, 2181, 2222, 3128, 3306, 3389,
        4444, 5432, 5601, 5900, 5985, 5986, 6379, 6667, 7000, 7001,
        8080, 8443, 8888, 9000, 9090, 9200, 9300, 9418, 9999, 10000,
        11211, 27017, 27018, 28017, 50000, 50070, 61616,
    ]

    if port_str.lower() == "top100":
        return sorted(TOP_100)
    if port_str.lower() == "all":
        return list(range(1, 65536))
    if "-" in port_str and "," not in port_str:
        start, end = port_str.split("-")
        return list(range(int(start), int(end) + 1))
    return [int(p.strip()) for p in port_str.split(",")]


def resolve_targets(target_str: str):
    """Resolve single IP, CIDR range, or hostname to list of IPs."""
    targets = []
    try:
        network = ipaddress.ip_network(target_str, strict=False)
        targets = [str(h) for h in network.hosts()]
    except ValueError:
        try:
            resolved = socket.gethostbyname(target_str)
            targets = [resolved]
            print(f"{Fore.CYAN}[*] Resolved {target_str} → {resolved}{Style.RESET_ALL}")
        except socket.gaierror:
            print(f"{Fore.RED}[!] Cannot resolve host: {target_str}{Style.RESET_ALL}")
            sys.exit(1)
    return targets


def build_parser():
    p = argparse.ArgumentParser(
        prog="stealth_scanner",
        description="StealthScan - Python network reconnaissance tool",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    # Target
    p.add_argument("-t", "--target", required=True,
                   help="Target IP, hostname, or CIDR (e.g. 192.168.1.0/24)")
    # Ports
    p.add_argument("-p", "--ports", default="top100",
                   help="Ports: '80', '1-1024', '22,80,443', 'top100', 'all'\n(default: top100)")
    # Scan type
    p.add_argument("--type", choices=["connect", "syn", "udp"], default="connect",
                   help="Scan type (default: connect).\n"
                        "  connect = TCP connect (no root needed)\n"
                        "  syn     = SYN stealth (root + scapy required)\n"
                        "  udp     = UDP scan (root + scapy recommended)")
    # Stealth options
    p.add_argument("--stealth", action="store_true",
                   help="Enable all stealth/evasion techniques")
    p.add_argument("--decoys", type=int, default=0, metavar="N",
                   help="Number of decoy IPs to inject (requires scapy + root)")
    p.add_argument("--fragment", action="store_true",
                   help="Fragment packets to bypass shallow IDS rules")
    p.add_argument("--spoof-port", action="store_true",
                   help="Use a trusted source port (80/443/53) to blend in")
    p.add_argument("--mimic-os", choices=["windows", "linux", "bsd", "cisco", "random"],
                   default="linux", help="TTL value to mimic (default: linux)")
    # Timing
    p.add_argument("--timing", choices=["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"],
                   default="normal",
                   help="Timing profile (default: normal). Use 'paranoid'/'sneaky' for max stealth.")
    p.add_argument("--slow", action="store_true",
                   help="Alias for --timing sneaky (slow random delays between probes)")
    # Detection features
    p.add_argument("--os-detect", action="store_true",
                   help="Attempt OS fingerprinting (requires root + scapy)")
    p.add_argument("--no-banner", action="store_true",
                   help="Disable banner grabbing")
    p.add_argument("--randomize", action="store_true",
                   help="Randomize port scan order")
    # Output
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Output file (.json, .html, or .txt detected automatically)")
    p.add_argument("--timeout", type=float, default=1.0,
                   help="Per-probe timeout in seconds (default: 1.0)")
    p.add_argument("-w", "--workers", type=int, default=0,
                   help="Max concurrent workers (0 = auto from timing profile)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show all ports including closed/filtered")
    return p


def main():
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()

    # ── Resolve targets & ports ──────────────────────────────────────────
    targets = resolve_targets(args.target)
    ports   = parse_ports(args.ports)

    print(f"{Fore.CYAN}[*] Targets  : {len(targets)} host(s) | Ports: {len(ports)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Scan type: {args.type.upper()}{Style.RESET_ALL}")

    # ── Timing profile ───────────────────────────────────────────────────
    from core.stealth import TimingProfile
    timing_name = "sneaky" if args.slow else args.timing
    timing = TimingProfile.get(timing_name)
    workers  = args.workers if args.workers > 0 else timing["workers"]
    delay    = timing["delay"]
    max_delay= timing["max_delay"]
    print(f"{Fore.CYAN}[*] Timing   : {timing_name.upper()} | Workers: {workers} | Delay: {delay}-{max_delay}s{Style.RESET_ALL}")

    # ── Stealth engine setup ─────────────────────────────────────────────
    from core.stealth import StealthEngine
    use_stealth = args.stealth or args.decoys > 0 or args.fragment or args.spoof_port

    stealth = StealthEngine(
        num_decoys=args.decoys if not args.stealth else max(args.decoys, 3),
        fragment=args.fragment or args.stealth,
        spoof_source_port=args.spoof_port or args.stealth,
        mimic_os=args.mimic_os,
        timing_jitter=True,
        min_delay=delay,
        max_delay=max_delay,
    )
    if use_stealth:
        print(f"{Fore.YELLOW}[*] Stealth  : ON | Decoys: {stealth.num_decoys} | "
              f"Fragment: {stealth.fragment} | SpoofPort: {stealth.spoof_source_port}{Style.RESET_ALL}")

    # ── Core scan ────────────────────────────────────────────────────────
    from core.scanner import CoreScanner
    start_time = time.time()

    scanner = CoreScanner(
        targets=targets,
        ports=ports,
        timeout=args.timeout,
        max_workers=workers,
        slow_mode=args.slow,
        randomize=args.randomize,
        grab_banners=not args.no_banner,
        scan_type=args.type,
        delay=delay,
    )
    results = scanner.run()
    duration = f"{time.time() - start_time:.2f}s"

    # ── Display results ──────────────────────────────────────────────────
    scanner.print_results()
    print(f"\n{Fore.CYAN}[*] Scan complete in {duration}{Style.RESET_ALL}")

    # ── OS Fingerprinting ────────────────────────────────────────────────
    # Always compute port-based OS guesses from scan results (no extra flag needed)
    from core.fingerprint import Fingerprinter
    open_results = [r for r in results if r.state in ("open", "open|filtered")]

    # Build per-host open port sets
    host_port_sets: dict = {}
    for r in open_results:
        host_port_sets.setdefault(r.host, set()).add(r.port)

    # Build os_info for reporter
    os_info: dict = {}
    for host, ports in host_port_sets.items():
        port_os = Fingerprinter.port_os_guess(ports)
        if port_os:
            os_info[host] = {"os": port_os, "method": "port-based", "ports": sorted(ports)}

    # --os-detect: additionally probe open ports with raw SYN for TTL+window data
    if args.os_detect:
        print(f"\n{Fore.CYAN}[*] Running deep OS fingerprinting on discovered ports...{Style.RESET_ALL}")
        for host in list(host_port_sets.keys())[:10]:  # limit to 10 hosts
            probe_ports = sorted(host_port_sets[host])[:3]  # use up to 3 known open ports
            info = {"os": "Unknown", "ttl": "?", "window": "?"}
            for port in probe_ports:
                result = Fingerprinter.active_os_probe_port(host, port, timeout=args.timeout)
                if result.get("ttl") != "?":
                    info = result
                    break
            # Port-based OS always wins if available
            if host in os_info:
                info["os"] = os_info[host]["os"]
            os_info[host] = info
            Fingerprinter.print_os_result(info, host)

    # ── Report output ────────────────────────────────────────────────────
    if args.output:
        from core.reporter import Reporter
        meta = {
            "targets": [args.target],
            "scan_type": args.type,
            "timing": timing_name,
            "duration": duration,
            "ports_probed": len(ports),
            "os_info": os_info,
        }
        reporter = Reporter(results, meta)
        out = args.output.lower()
        if out.endswith(".json"):
            reporter.to_json(args.output)
        elif out.endswith(".html"):
            reporter.to_html(args.output)
        else:
            reporter.to_txt(args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
