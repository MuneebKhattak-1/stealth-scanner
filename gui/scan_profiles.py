"""
StealthScan GUI - Scan Profiles
Pre-defined scan configurations mirroring Zenmap's profile system.
"""


SCAN_PROFILES = {
    "Auto-Discovery Scan": {
        "scan_type": "connect",
        "ports": "top100",
        "stealth": False,
        "auto_discovery": True,
        "discover_only": False,
        "description": "Automatically detect local subnet, find devices via ARP, and port scan them",
    },
    "Discover-Only (Network Sweep)": {
        "scan_type": "connect",
        "ports": "none",
        "stealth": False,
        "auto_discovery": True,
        "discover_only": True,
        "description": "Find active devices on the local network via ARP (No port scan)",
    },
    "Quick Scan": {
        "scan_type": "connect",
        "ports": "top100",
        "stealth": False,
        "decoys": 0,
        "fragment": False,
        "spoof_port": False,
        "mimic_os": "linux",
        "timing": "normal",
        "os_detect": False,
        "no_banner": False,
        "randomize": False,
        "timeout": 1.0,
        "workers": 0,
        "description": "Fast TCP connect scan on top 100 ports",
    },
    "Intense Scan": {
        "scan_type": "connect",
        "ports": "1-1024",
        "stealth": False,
        "decoys": 0,
        "fragment": False,
        "spoof_port": False,
        "mimic_os": "linux",
        "timing": "aggressive",
        "os_detect": True,
        "no_banner": False,
        "randomize": False,
        "timeout": 1.0,
        "workers": 0,
        "description": "Aggressive scan on first 1024 ports + OS detection",
    },
    "SYN Stealth Scan": {
        "scan_type": "syn",
        "ports": "top100",
        "stealth": True,
        "decoys": 0,
        "fragment": False,
        "spoof_port": False,
        "mimic_os": "linux",
        "timing": "sneaky",
        "os_detect": False,
        "no_banner": True,
        "randomize": True,
        "timeout": 1.5,
        "workers": 0,
        "description": "Half-open SYN stealth scan (requires root/admin)",
    },
    "Full Stealth": {
        "scan_type": "syn",
        "ports": "top100",
        "stealth": True,
        "decoys": 5,
        "fragment": True,
        "spoof_port": True,
        "mimic_os": "random",
        "timing": "paranoid",
        "os_detect": True,
        "no_banner": True,
        "randomize": True,
        "timeout": 2.0,
        "workers": 0,
        "description": "Maximum evasion: decoys + fragmentation + spoofing",
    },
    "UDP Scan": {
        "scan_type": "udp",
        "ports": "top100",
        "stealth": False,
        "decoys": 0,
        "fragment": False,
        "spoof_port": False,
        "mimic_os": "linux",
        "timing": "normal",
        "os_detect": False,
        "no_banner": True,
        "randomize": False,
        "timeout": 2.0,
        "workers": 0,
        "description": "UDP port scan",
    },
    "Full Port Scan": {
        "scan_type": "connect",
        "ports": "all",
        "stealth": False,
        "decoys": 0,
        "fragment": False,
        "spoof_port": False,
        "mimic_os": "linux",
        "timing": "aggressive",
        "os_detect": True,
        "no_banner": False,
        "randomize": True,
        "timeout": 0.5,
        "workers": 0,
        "description": "Scan all 65535 ports (takes a long time)",
    },
}


def profile_to_command(target: str, profile_name: str, profile: dict, ports_override: str = "") -> str:
    """Generate the equivalent CLI command string for display."""
    ports = ports_override if ports_override else profile.get("ports", "top100")
    
    if profile.get("discover_only"):
        cmd = "python stealth_scanner.py -d"
    elif profile.get("auto_discovery"):
        cmd = f"python stealth_scanner.py -a -p {ports} --type {profile.get('scan_type', 'connect')}"
    else:
        cmd = f"python stealth_scanner.py -t {target} -p {ports} --type {profile.get('scan_type', 'connect')}"

    if profile.get("stealth"):
        cmd += " --stealth"
    if profile.get("decoys", 0) > 0:
        cmd += f" --decoys {profile['decoys']}"
    if profile.get("fragment"):
        cmd += " --fragment"
    if profile.get("spoof_port"):
        cmd += " --spoof-port"
    if profile.get("mimic_os", "linux") != "linux":
        cmd += f" --mimic-os {profile['mimic_os']}"
    if profile.get("timing", "normal") != "normal":
        cmd += f" --timing {profile['timing']}"
    if profile.get("os_detect"):
        cmd += " --os-detect"
    if profile.get("no_banner"):
        cmd += " --no-banner"
    if profile.get("randomize"):
        cmd += " --randomize"
    if profile.get("timeout", 1.0) != 1.0:
        cmd += f" --timeout {profile['timeout']}"

    return cmd
