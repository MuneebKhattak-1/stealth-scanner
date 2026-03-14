"""
StealthScan GUI - Results View Widgets
Provides tabbed result views: Scan Output, Ports/Hosts table, Host Details, Topology.
"""

import tkinter as tk
from tkinter import ttk


# ══════════════════════════════════════════════════════════════════════════════
#  Color Palette (dark hacker theme)
# ══════════════════════════════════════════════════════════════════════════════

COLORS = {
    "bg_dark":      "#0a0e14",
    "bg_panel":     "#0d1117",
    "bg_card":      "#161b22",
    "bg_header":    "#1c2128",
    "border":       "#30363d",
    "text":         "#c9d1d9",
    "text_dim":     "#8b949e",
    "text_bright":  "#e6edf3",
    "accent":       "#58a6ff",
    "green":        "#3fb950",
    "yellow":       "#d29922",
    "red":          "#f85149",
    "orange":       "#f0883e",
    "purple":       "#bc8cff",
    "cyan":         "#39d2e0",
}

# Tag colors for the output text widget
TEXT_TAGS = {
    "info":     {"foreground": COLORS["cyan"]},
    "header":   {"foreground": COLORS["accent"], "font": ("Consolas", 10, "bold")},
    "warning":  {"foreground": COLORS["yellow"]},
    "error":    {"foreground": COLORS["red"], "font": ("Consolas", 10, "bold")},
    "success":  {"foreground": COLORS["green"], "font": ("Consolas", 10, "bold")},
    "open":     {"foreground": COLORS["green"]},
    "filtered": {"foreground": COLORS["yellow"]},
    "stealth":  {"foreground": COLORS["purple"]},
    "os":       {"foreground": COLORS["orange"]},
    "dim":      {"foreground": COLORS["text_dim"]},
    "default":  {"foreground": COLORS["text"]},
}


# ══════════════════════════════════════════════════════════════════════════════
#  Scan Output Tab — scrolling text log
# ══════════════════════════════════════════════════════════════════════════════

class ScanOutputView(tk.Frame):
    """Scrollable text output showing raw scan log with color tags."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=COLORS["bg_dark"], **kwargs)

        # Text widget with scrollbar
        self.text = tk.Text(
            self,
            bg=COLORS["bg_dark"],
            fg=COLORS["text"],
            insertbackground=COLORS["accent"],
            selectbackground=COLORS["accent"],
            selectforeground=COLORS["bg_dark"],
            font=("Consolas", 10),
            wrap=tk.WORD,
            relief=tk.FLAT,
            padx=12,
            pady=8,
            state=tk.DISABLED,
            cursor="arrow",
            borderwidth=0,
            highlightthickness=0,
        )

        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.text.yview)
        self.text.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Register color tags
        for tag_name, tag_config in TEXT_TAGS.items():
            self.text.tag_configure(tag_name, **tag_config)

    def append(self, text: str, tag: str = "default"):
        """Append a line of text with the given color tag."""
        self.text.configure(state=tk.NORMAL)
        self.text.insert(tk.END, text + "\n", tag)
        self.text.see(tk.END)
        self.text.configure(state=tk.DISABLED)

    def clear(self):
        """Clear all text."""
        self.text.configure(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        self.text.configure(state=tk.DISABLED)


# ══════════════════════════════════════════════════════════════════════════════
#  Ports/Hosts Table Tab — Treeview table
# ══════════════════════════════════════════════════════════════════════════════

class PortsTableView(tk.Frame):
    """Sortable table showing discovered ports with host, port, state, service, banner, OS."""

    COLUMNS = [
        ("host",    "Host",    160),
        ("port",    "Port",    70),
        ("state",   "State",   100),
        ("service", "Service", 120),
        ("banner",  "Banner",  280),
        ("os",      "OS",      140),
    ]

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=COLORS["bg_dark"], **kwargs)

        # Create Treeview
        columns = [c[0] for c in self.COLUMNS]
        self.tree = ttk.Treeview(self, columns=columns, show="headings", selectmode="browse")

        for col_id, col_name, col_width in self.COLUMNS:
            self.tree.heading(col_id, text=col_name, command=lambda c=col_id: self._sort_column(c, False))
            self.tree.column(col_id, width=col_width, minwidth=50)

        # Scrollbars
        vsb = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(self, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Layout
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Tags for rows
        self.tree.tag_configure("open", foreground=COLORS["green"])
        self.tree.tag_configure("filtered", foreground=COLORS["yellow"])
        self.tree.tag_configure("closed", foreground=COLORS["red"])

        self._sort_reverse = {}

    def add_result(self, host, port, state, service, banner, os_guess):
        """Add a scan result row to the table."""
        tag = "open" if state == "open" else ("filtered" if "filtered" in state else "closed")
        self.tree.insert("", tk.END, values=(host, port, state, service, banner[:60] if banner else "", os_guess), tags=(tag,))

    def clear(self):
        """Clear all rows."""
        for item in self.tree.get_children():
            self.tree.delete(item)

    def _sort_column(self, col, reverse):
        """Sort treeview column."""
        data = [(self.tree.set(item, col), item) for item in self.tree.get_children()]
        # Try numeric sort for port column
        if col == "port":
            try:
                data.sort(key=lambda t: int(t[0]), reverse=reverse)
            except ValueError:
                data.sort(reverse=reverse)
        else:
            data.sort(reverse=reverse)
        for index, (val, item) in enumerate(data):
            self.tree.move(item, "", index)
        self.tree.heading(col, command=lambda: self._sort_column(col, not reverse))

    def get_all_results(self):
        """Return all results as list of dicts."""
        results = []
        for item in self.tree.get_children():
            values = self.tree.item(item, "values")
            results.append({
                "host": values[0],
                "port": values[1],
                "state": values[2],
                "service": values[3],
                "banner": values[4],
                "os": values[5],
            })
        return results


# ══════════════════════════════════════════════════════════════════════════════
#  Host Details Tab — per-host info
# ══════════════════════════════════════════════════════════════════════════════

class HostDetailsView(tk.Frame):
    """Shows detailed info for each discovered host with OS fingerprint and services."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=COLORS["bg_dark"], **kwargs)

        # Left: host list
        left_frame = tk.Frame(self, bg=COLORS["bg_panel"], width=200)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 1))
        left_frame.pack_propagate(False)

        host_label = tk.Label(left_frame, text="DISCOVERED HOSTS", font=("Segoe UI", 9, "bold"),
                              bg=COLORS["bg_panel"], fg=COLORS["accent"], anchor="w")
        host_label.pack(fill=tk.X, padx=10, pady=(10, 5))

        self.host_listbox = tk.Listbox(
            left_frame,
            bg=COLORS["bg_card"],
            fg=COLORS["text"],
            selectbackground=COLORS["accent"],
            selectforeground=COLORS["bg_dark"],
            font=("Consolas", 10),
            relief=tk.FLAT,
            borderwidth=0,
            highlightthickness=1,
            highlightcolor=COLORS["border"],
            highlightbackground=COLORS["border"],
        )
        self.host_listbox.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        self.host_listbox.bind("<<ListboxSelect>>", self._on_host_select)

        # Right: detail panel
        self.detail_frame = tk.Frame(self, bg=COLORS["bg_dark"])
        self.detail_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.detail_text = tk.Text(
            self.detail_frame,
            bg=COLORS["bg_dark"],
            fg=COLORS["text"],
            font=("Consolas", 10),
            wrap=tk.WORD,
            relief=tk.FLAT,
            padx=16,
            pady=12,
            state=tk.DISABLED,
            cursor="arrow",
            borderwidth=0,
            highlightthickness=0,
        )
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        # Tags
        self.detail_text.tag_configure("title", foreground=COLORS["accent"], font=("Segoe UI", 14, "bold"))
        self.detail_text.tag_configure("label", foreground=COLORS["text_dim"], font=("Segoe UI", 9, "bold"))
        self.detail_text.tag_configure("value", foreground=COLORS["text_bright"], font=("Consolas", 10))
        self.detail_text.tag_configure("open", foreground=COLORS["green"])
        self.detail_text.tag_configure("os", foreground=COLORS["orange"], font=("Segoe UI", 11, "bold"))
        self.detail_text.tag_configure("divider", foreground=COLORS["border"])

        self._host_data = {}  # host -> {os_info, ports: [...]}

    def add_host_port(self, host, port, state, service, banner, os_guess):
        """Record a port result for a host."""
        if host not in self._host_data:
            self._host_data[host] = {"os_info": {}, "ports": []}
            self.host_listbox.insert(tk.END, f"  {host}")
        self._host_data[host]["ports"].append({
            "port": port, "state": state, "service": service,
            "banner": banner, "os_guess": os_guess,
        })

    def set_os_info(self, host, info):
        """Set OS fingerprint info for a host."""
        if host not in self._host_data:
            self._host_data[host] = {"os_info": {}, "ports": []}
            self.host_listbox.insert(tk.END, f"  {host}")
        self._host_data[host]["os_info"] = info if isinstance(info, dict) else {"os": str(info)}

    def clear(self):
        """Clear all host data."""
        self._host_data.clear()
        self.host_listbox.delete(0, tk.END)
        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.configure(state=tk.DISABLED)

    def _on_host_select(self, event):
        sel = self.host_listbox.curselection()
        if not sel:
            return
        host = self.host_listbox.get(sel[0]).strip()
        self._show_host_detail(host)

    def _show_host_detail(self, host):
        data = self._host_data.get(host)
        if not data:
            return

        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)

        # Host title
        self.detail_text.insert(tk.END, f"🖥  {host}\n", "title")
        self.detail_text.insert(tk.END, "─" * 50 + "\n\n", "divider")

        # OS Info
        os_info = data.get("os_info", {})
        os_name = os_info.get("os", "Unknown")
        self.detail_text.insert(tk.END, "  OS FINGERPRINT\n", "label")
        self.detail_text.insert(tk.END, f"  {os_name}\n", "os")
        if os_info.get("ttl") and os_info["ttl"] != "?":
            self.detail_text.insert(tk.END, f"  TTL: {os_info['ttl']}  |  ", "value")
            self.detail_text.insert(tk.END, f"Window: {os_info.get('window', '?')}  |  ", "value")
            self.detail_text.insert(tk.END, f"Method: {os_info.get('method', 'packet')}\n", "value")
        self.detail_text.insert(tk.END, "\n", "value")

        # Ports
        ports = data.get("ports", [])
        open_ports = [p for p in ports if p["state"] in ("open", "open|filtered")]
        self.detail_text.insert(tk.END, f"  OPEN PORTS ({len(open_ports)})\n", "label")
        self.detail_text.insert(tk.END, "  " + "─" * 48 + "\n", "divider")
        self.detail_text.insert(tk.END, f"  {'PORT':<8}{'STATE':<14}{'SERVICE':<16}BANNER\n", "label")
        self.detail_text.insert(tk.END, "  " + "─" * 48 + "\n", "divider")

        for p in sorted(open_ports, key=lambda x: x["port"]):
            svc = p["service"] if p["service"] else "—"
            banner = p["banner"][:35] if p["banner"] else "—"
            self.detail_text.insert(tk.END,
                f"  {str(p['port']):<8}{p['state']:<14}{svc:<16}{banner}\n", "open")

        self.detail_text.insert(tk.END, "\n", "value")
        self.detail_text.configure(state=tk.DISABLED)


# ══════════════════════════════════════════════════════════════════════════════
#  Topology Tab — simple canvas visualization
# ══════════════════════════════════════════════════════════════════════════════

class TopologyView(tk.Frame):
    """Simple network topology visualization using Canvas."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=COLORS["bg_dark"], **kwargs)

        self.canvas = tk.Canvas(
            self,
            bg=COLORS["bg_dark"],
            highlightthickness=0,
            borderwidth=0,
        )
        self.canvas.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self._hosts = {}  # host -> {os, ports_count, x, y}
        self._tooltip = None

    def clear(self):
        self.canvas.delete("all")
        self._hosts.clear()

    def add_host(self, host, os_name="Unknown", port_count=0):
        self._hosts[host] = {"os": os_name, "ports": port_count}
        self._redraw()

    def _redraw(self):
        self.canvas.delete("all")
        if not self._hosts:
            self.canvas.create_text(
                self.canvas.winfo_width() // 2 or 400,
                self.canvas.winfo_height() // 2 or 250,
                text="No hosts discovered yet",
                fill=COLORS["text_dim"],
                font=("Segoe UI", 12),
            )
            return

        self.canvas.update_idletasks()
        w = max(self.canvas.winfo_width(), 600)
        h = max(self.canvas.winfo_height(), 400)

        # Draw scanner node at center
        cx, cy = w // 2, h // 2
        scanner_r = 28
        self.canvas.create_oval(
            cx - scanner_r, cy - scanner_r, cx + scanner_r, cy + scanner_r,
            fill=COLORS["accent"], outline=COLORS["text_bright"], width=2,
        )
        self.canvas.create_text(cx, cy, text="YOU", fill=COLORS["bg_dark"],
                                font=("Segoe UI", 9, "bold"))

        # Draw host nodes in a circle around the scanner
        import math
        hosts = list(self._hosts.items())
        n = len(hosts)
        radius = min(w, h) * 0.35

        for i, (host, info) in enumerate(hosts):
            angle = (2 * math.pi * i / n) - (math.pi / 2)
            hx = cx + radius * math.cos(angle)
            hy = cy + radius * math.sin(angle)

            # Color by OS
            os_name = info.get("os", "").lower()
            if "windows" in os_name:
                color = COLORS["accent"]
            elif "linux" in os_name:
                color = COLORS["green"]
            elif "bsd" in os_name or "mac" in os_name:
                color = COLORS["orange"]
            else:
                color = COLORS["text_dim"]

            # Draw connection line
            self.canvas.create_line(cx, cy, hx, hy, fill=COLORS["border"], width=1, dash=(4, 4))

            # Draw host node
            node_r = 20 + min(info.get("ports", 0) * 2, 15)
            self.canvas.create_oval(
                hx - node_r, hy - node_r, hx + node_r, hy + node_r,
                fill=color, outline=COLORS["text_bright"], width=1,
            )

            # Host label
            label = host.split(".")[-1] if "." in host else host
            self.canvas.create_text(hx, hy, text=label, fill=COLORS["bg_dark"],
                                    font=("Consolas", 8, "bold"))

            # OS label below
            os_label = info.get("os", "?")
            if len(os_label) > 12:
                os_label = os_label[:12] + "…"
            self.canvas.create_text(hx, hy + node_r + 14, text=os_label,
                                    fill=COLORS["text_dim"], font=("Segoe UI", 8))

            # IP label
            self.canvas.create_text(hx, hy + node_r + 28, text=host,
                                    fill=COLORS["text_dim"], font=("Consolas", 7))

            # Port count badge
            if info.get("ports", 0) > 0:
                badge_x = hx + node_r - 4
                badge_y = hy - node_r + 4
                self.canvas.create_oval(badge_x - 10, badge_y - 10, badge_x + 10, badge_y + 10,
                                        fill=COLORS["green"], outline="")
                self.canvas.create_text(badge_x, badge_y, text=str(info["ports"]),
                                        fill=COLORS["bg_dark"], font=("Segoe UI", 7, "bold"))
