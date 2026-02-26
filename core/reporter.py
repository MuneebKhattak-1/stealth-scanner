"""
StealthScanner - Report Generator
Outputs scan results as JSON, plain text, and styled HTML.
"""

import json
import datetime
from pathlib import Path
from typing import List, Dict, Any
from colorama import Fore, Style


class Reporter:
    def __init__(self, results: List[Any], meta: Dict[str, Any]):
        """
        results : list of ScanResult objects
        meta    : dict with scan metadata (targets, scan_type, duration, os_info, etc.)
        """
        self.results = results
        self.meta = meta
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ------------------------------------------------------------------ #
    #  JSON                                                                #
    # ------------------------------------------------------------------ #

    def to_json(self, output_path: str):
        data = {
            "scan_metadata": {
                "timestamp": self.timestamp,
                **self.meta,
            },
            "results": [r.to_dict() for r in self.results if r.state in ("open", "open|filtered")]
        }
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"{Fore.GREEN}[+] JSON report saved: {output_path}{Style.RESET_ALL}")

    # ------------------------------------------------------------------ #
    #  Plain text                                                          #
    # ------------------------------------------------------------------ #

    def to_txt(self, output_path: str):
        lines = [
            "=" * 60,
            "  STEALTHSCAN REPORT",
            f"  Generated: {self.timestamp}",
            "=" * 60,
            f"  Targets  : {', '.join(self.meta.get('targets', []))}",
            f"  Scan Type: {self.meta.get('scan_type', 'N/A')}",
            f"  Duration : {self.meta.get('duration', 'N/A')}",
            "=" * 60,
            f"{'HOST':<18}{'PORT':<8}{'STATE':<12}SERVICE",
            "-" * 60,
        ]
        for r in self.results:
            if r.state in ("open", "open|filtered"):
                lines.append(f"{r.host:<18}{r.port:<8}{r.state:<12}{r.service}")
                if r.banner:
                    lines.append(f"  Banner: {r.banner[:80]}")
        lines.append("=" * 60)

        with open(output_path, "w") as f:
            f.write("\n".join(lines))
        print(f"{Fore.GREEN}[+] Text report saved: {output_path}{Style.RESET_ALL}")

    # ------------------------------------------------------------------ #
    #  HTML                                                                #
    # ------------------------------------------------------------------ #

    def to_html(self, output_path: str):
        open_results = [r for r in self.results if r.state in ("open", "open|filtered")]

        rows = ""
        for r in open_results:
            state_cls = "open" if r.state == "open" else "filtered"
            rows += (
                f"<tr>"
                f"<td>{r.host}</td>"
                f"<td>{r.port}</td>"
                f"<td class='state {state_cls}'>{r.state}</td>"
                f"<td>{r.service}</td>"
                f"<td class='banner'>{r.banner[:80] if r.banner else '—'}</td>"
                f"</tr>\n"
            )

        os_info = self.meta.get("os_info", {})
        os_rows = ""
        for host, info in os_info.items():
            os_rows += (
                f"<tr><td>{host}</td>"
                f"<td>{info.get('os','?')}</td>"
                f"<td>{info.get('ttl','?')}</td>"
                f"<td>{info.get('window','?')}</td></tr>\n"
            )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>StealthScan Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Courier New', monospace;
      background: #0d1117;
      color: #c9d1d9;
      padding: 2rem;
    }}
    h1 {{ color: #58a6ff; margin-bottom: 0.25rem; font-size: 1.8rem; }}
    .subtitle {{ color: #8b949e; font-size: 0.9rem; margin-bottom: 2rem; }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .meta-card {{
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 1rem;
    }}
    .meta-card .label {{ color: #8b949e; font-size: 0.75rem; text-transform: uppercase; }}
    .meta-card .value {{ color: #e6edf3; font-size: 1rem; margin-top: 0.25rem; }}
    h2 {{ color: #58a6ff; margin: 2rem 0 1rem; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }}
    table {{ width: 100%; border-collapse: collapse; background: #161b22;
             border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }}
    thead {{ background: #21262d; }}
    th {{ padding: 0.75rem 1rem; text-align: left; color: #8b949e;
          font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    td {{ padding: 0.6rem 1rem; border-top: 1px solid #21262d; font-size: 0.85rem; }}
    tr:hover {{ background: #1c2128; }}
    .state.open     {{ color: #3fb950; font-weight: bold; }}
    .state.filtered {{ color: #d29922; font-weight: bold; }}
    .banner {{ color: #8b949e; font-size: 0.78rem; max-width: 400px;
               overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .badge {{
      display: inline-block;
      background: #1f6feb;
      color: #e6edf3;
      border-radius: 20px;
      padding: 0.2rem 0.75rem;
      font-size: 0.75rem;
      margin-left: 0.5rem;
    }}
    footer {{ margin-top: 3rem; text-align: center; color: #484f58; font-size: 0.75rem; }}
  </style>
</head>
<body>
  <h1>🔍 StealthScan Report <span class="badge">{len(open_results)} open ports</span></h1>
  <p class="subtitle">Generated: {self.timestamp}</p>

  <div class="meta-grid">
    <div class="meta-card">
      <div class="label">Targets</div>
      <div class="value">{', '.join(self.meta.get('targets', []))}</div>
    </div>
    <div class="meta-card">
      <div class="label">Scan Type</div>
      <div class="value">{self.meta.get('scan_type', 'N/A').upper()}</div>
    </div>
    <div class="meta-card">
      <div class="label">Duration</div>
      <div class="value">{self.meta.get('duration', 'N/A')}</div>
    </div>
    <div class="meta-card">
      <div class="label">Ports Probed</div>
      <div class="value">{self.meta.get('ports_probed', 'N/A')}</div>
    </div>
  </div>

  <h2>Open Ports</h2>
  <table>
    <thead>
      <tr><th>Host</th><th>Port</th><th>State</th><th>Service</th><th>Banner</th></tr>
    </thead>
    <tbody>{rows if rows else '<tr><td colspan="5" style="text-align:center;color:#8b949e">No open ports found</td></tr>'}</tbody>
  </table>

  {'<h2>OS Fingerprints</h2><table><thead><tr><th>Host</th><th>OS Guess</th><th>TTL</th><th>Window</th></tr></thead><tbody>' + os_rows + '</tbody></table>' if os_rows else ''}

  <footer>StealthScan | For authorized use only</footer>
</body>
</html>"""

        with open(output_path, "w") as f:
            f.write(html)
        print(f"{Fore.GREEN}[+] HTML report saved: {output_path}{Style.RESET_ALL}")
