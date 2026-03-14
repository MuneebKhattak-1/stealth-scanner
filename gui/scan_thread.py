"""
StealthScan GUI - Scan Thread
Runs scans in a background thread, posting results to a queue for the GUI.
"""

import sys
import time
import queue
import socket
import random
import threading
import ipaddress
from datetime import datetime


# Message types for the queue
MSG_LOG = "log"
MSG_RESULT = "result"
MSG_PROGRESS = "progress"
MSG_COMPLETE = "complete"
MSG_ERROR = "error"
MSG_OS_INFO = "os_info"


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
        if not targets:
            targets = [str(network.network_address)]
    except ValueError:
        try:
            resolved = socket.gethostbyname(target_str)
            targets = [resolved]
        except socket.gaierror:
            return []
    return targets


class ScanThread(threading.Thread):
    """
    Background thread that runs the scan and posts messages to a queue.
    The GUI polls this queue to update the display.
    """

    def __init__(self, target: str, ports_str: str, profile: dict, msg_queue: queue.Queue):
        super().__init__(daemon=True)
        self.target = target
        self.ports_str = ports_str
        self.profile = profile
        self.msg_queue = msg_queue
        self._cancel = threading.Event()

    def cancel(self):
        """Signal the thread to stop scanning."""
        self._cancel.set()

    def is_cancelled(self):
        return self._cancel.is_set()

    def log(self, text: str, tag: str = "info"):
        """Post a log message to the queue."""
        self.msg_queue.put((MSG_LOG, {"text": text, "tag": tag}))

    def run(self):
        try:
            self._run_scan()
        except Exception as e:
            self.msg_queue.put((MSG_ERROR, {"text": f"Scan error: {e}"}))

    def _run_scan(self):
        start_time = time.time()
        profile = self.profile

        # Header
        self.log("=" * 65, "header")
        self.log("  StealthScan v1.1 — Network Reconnaissance Tool", "header")
        self.log("  [!] For authorized penetration testing ONLY", "warning")
        self.log("=" * 65, "header")
        self.log("")

        # Resolve targets
        self.log(f"[*] Resolving target: {self.target}", "info")
        targets = resolve_targets(self.target)
        if not targets:
            self.log(f"[!] Cannot resolve host: {self.target}", "error")
            self.msg_queue.put((MSG_COMPLETE, {"duration": "0s", "total": 0, "open": 0}))
            return

        if targets[0] != self.target:
            self.log(f"[*] Resolved {self.target} → {targets[0]}", "info")

        # Parse ports
        try:
            ports = parse_ports(self.ports_str)
        except Exception as e:
            self.log(f"[!] Invalid port specification: {e}", "error")
            self.msg_queue.put((MSG_COMPLETE, {"duration": "0s", "total": 0, "open": 0}))
            return

        self.log(f"[*] Targets  : {len(targets)} host(s) | Ports: {len(ports)}", "info")
        self.log(f"[*] Scan type: {profile['scan_type'].upper()}", "info")

        # Timing profile
        from core.stealth import TimingProfile
        timing_name = profile.get("timing", "normal")
        timing = TimingProfile.get(timing_name)
        workers = profile.get("workers", 0)
        if workers <= 0:
            workers = timing["workers"]
        delay = timing["delay"]
        max_delay = timing["max_delay"]
        self.log(f"[*] Timing   : {timing_name.upper()} | Workers: {workers} | Delay: {delay}-{max_delay}s", "info")

        # Stealth status
        use_stealth = profile.get("stealth", False)
        if use_stealth:
            decoys = profile.get("decoys", 0)
            frag = profile.get("fragment", False)
            spoof = profile.get("spoof_port", False)
            self.log(f"[*] Stealth  : ON | Decoys: {decoys} | Fragment: {frag} | SpoofPort: {spoof}", "stealth")

        self.log("")
        self.log(f"[*] Starting {profile['scan_type'].upper()} scan on {len(targets)} host(s), "
                 f"{len(ports)} port(s)...", "info")
        self.log("")

        if self.is_cancelled():
            self.log("[!] Scan cancelled.", "warning")
            self.msg_queue.put((MSG_COMPLETE, {"duration": "0s", "total": 0, "open": 0}))
            return

        # Run the core scanner
        from core.scanner import CoreScanner
        scanner = CoreScanner(
            targets=targets,
            ports=ports,
            timeout=profile.get("timeout", 1.0),
            max_workers=workers,
            slow_mode=False,
            randomize=profile.get("randomize", False),
            grab_banners=not profile.get("no_banner", False),
            scan_type=profile["scan_type"],
            delay=delay,
        )

        # We run the scan — it uses ThreadPoolExecutor internally
        # We'll redirect its tqdm output by running it directly
        results = self._run_scanner_with_progress(scanner, targets, ports)

        duration = f"{time.time() - start_time:.2f}s"

        if self.is_cancelled():
            self.log("\n[!] Scan cancelled by user.", "warning")
            self.msg_queue.put((MSG_COMPLETE, {"duration": duration, "total": len(results), "open": 0}))
            return

        # Collect open results (already posted to GUI in real-time by _run_scanner_with_progress)
        open_results = [r for r in results if r.state in ("open", "open|filtered")]

        # Log results
        if open_results:
            self.log("")
            self.log(f"{'HOST':<18}{'PORT':<8}{'STATE':<12}{'SERVICE':<16}BANNER", "header")
            self.log("─" * 75, "dim")
            for r in open_results:
                svc = f"[{r.service}]" if r.service else ""
                banner = f'"{r.banner[:40]}"' if r.banner else ""
                tag = "open" if r.state == "open" else "filtered"
                self.log(f"{r.host:<18}{str(r.port):<8}{r.state:<12}{svc:<16}{banner}", tag)
        else:
            self.log("[!] No open ports found.", "warning")

        # OS fingerprinting
        from core.fingerprint import Fingerprinter
        host_port_sets = {}
        for r in open_results:
            host_port_sets.setdefault(r.host, set()).add(r.port)

        os_info = {}
        for host, host_ports in host_port_sets.items():
            port_os = Fingerprinter.port_os_guess(host_ports)
            if port_os:
                os_info[host] = {"os": port_os, "method": "port-based", "ports": sorted(host_ports)}

        # Deep OS detect
        if profile.get("os_detect", False) and host_port_sets:
            self.log("")
            self.log("[*] Running deep OS fingerprinting...", "info")
            for host in list(host_port_sets.keys())[:10]:
                probe_ports = sorted(host_port_sets[host])[:3]
                info = {"os": "Unknown", "ttl": "?", "window": "?"}
                for port in probe_ports:
                    result = Fingerprinter.active_os_probe_port(host, port, timeout=profile.get("timeout", 1.0))
                    if result.get("ttl") != "?":
                        info = result
                        break
                if host in os_info:
                    info["os"] = os_info[host]["os"]
                os_info[host] = info
                self.log(f"  {host} → OS: {info.get('os', '?')} | TTL: {info.get('ttl', '?')} | "
                         f"Window: {info.get('window', '?')}", "os")

        # Post OS info
        if os_info:
            self.log("")
            self.log(f"{'HOST':<18} OS FINGERPRINT", "header")
            self.log("─" * 50, "dim")
            for host, info in os_info.items():
                os_name = info.get("os", "?") if isinstance(info, dict) else str(info)
                self.log(f"{host:<18} {os_name}", "os")
                self.msg_queue.put((MSG_OS_INFO, {"host": host, "info": info}))

        self.log("")
        self.log(f"[*] Scan complete in {duration}", "success")
        self.log(f"[*] {len(open_results)} open port(s) found on {len(host_port_sets)} host(s)", "success")

        self.msg_queue.put((MSG_COMPLETE, {
            "duration": duration,
            "total": len(results),
            "open": len(open_results),
            "os_info": os_info,
            "results": results,
        }))

    def _run_scanner_with_progress(self, scanner, targets, ports):
        """Run the scanner with progress updates posted to the GUI."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        port_list = scanner.ports.copy()
        if scanner.randomize:
            random.shuffle(port_list)

        tasks = [(host, port) for host in targets for port in port_list]
        if scanner.randomize:
            random.shuffle(tasks)

        total = len(tasks)
        results = []
        completed = 0

        with ThreadPoolExecutor(max_workers=scanner.max_workers) as executor:
            futures = {executor.submit(scanner._probe, host, port): (host, port)
                       for host, port in tasks}
            for future in as_completed(futures):
                if self.is_cancelled():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                result = future.result()
                if result:
                    results.append(result)
                    # Post real-time result for live table updates
                    if result.state in ("open", "open|filtered"):
                        self.msg_queue.put((MSG_RESULT, {
                            "host": result.host,
                            "port": result.port,
                            "state": result.state,
                            "service": result.service,
                            "banner": result.banner,
                            "os_guess": result.os_guess,
                        }))
                completed += 1
                if completed % max(1, total // 100) == 0 or completed == total:
                    pct = int(completed / total * 100)
                    self.msg_queue.put((MSG_PROGRESS, {"current": completed, "total": total, "percent": pct}))

        scanner.results = sorted(results, key=lambda r: (r.host, r.port))
        return scanner.results
