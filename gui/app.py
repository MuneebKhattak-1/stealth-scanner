"""
StealthScan GUI - Main Application Window
Zenmap-style dark-themed network scanner interface.
"""

import os
import sys
import queue
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime

# Add project root to path so we can import core modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gui.scan_profiles import SCAN_PROFILES, profile_to_command
from gui.scan_thread import ScanThread, MSG_LOG, MSG_RESULT, MSG_PROGRESS, MSG_COMPLETE, MSG_ERROR, MSG_OS_INFO
from gui.results_view import (
    COLORS, ScanOutputView, PortsTableView, HostDetailsView, TopologyView,
)


class StealthScanApp(tk.Tk):
    """Main application window — Zenmap-style layout."""

    def __init__(self):
        super().__init__()

        self.title("StealthScan v1.1 — Network Reconnaissance Tool")
        self.geometry("1100x720")
        self.minsize(900, 550)
        self.configure(bg=COLORS["bg_dark"])

        # Set window icon (optional, won't crash if missing)
        try:
            self.iconbitmap(default="")
        except Exception:
            pass

        # State
        self._scan_thread = None
        self._msg_queue = queue.Queue()
        self._scan_start_time = None
        self._timer_id = None
        self._scan_results = []
        self._scan_os_info = {}

        # Build UI
        self._setup_styles()
        self._build_menu()
        self._build_top_bar()
        self._build_command_bar()
        self._build_notebook()
        self._build_status_bar()

        # Start polling
        self._poll_queue()

        # Bind resize for topology
        self.bind("<Configure>", self._on_resize)

    # ================================================================== #
    #  STYLES                                                             #
    # ================================================================== #

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        # General
        style.configure(".", background=COLORS["bg_dark"], foreground=COLORS["text"],
                         borderwidth=0, focuscolor=COLORS["accent"])

        # Notebook
        style.configure("TNotebook", background=COLORS["bg_dark"], borderwidth=0)
        style.configure("TNotebook.Tab",
                         background=COLORS["bg_header"],
                         foreground=COLORS["text_dim"],
                         padding=[14, 6],
                         font=("Segoe UI", 9, "bold"))
        style.map("TNotebook.Tab",
                   background=[("selected", COLORS["bg_card"])],
                   foreground=[("selected", COLORS["accent"])])

        # Treeview (for ports table)
        style.configure("Treeview",
                         background=COLORS["bg_card"],
                         foreground=COLORS["text"],
                         fieldbackground=COLORS["bg_card"],
                         borderwidth=0,
                         font=("Consolas", 9),
                         rowheight=26)
        style.configure("Treeview.Heading",
                         background=COLORS["bg_header"],
                         foreground=COLORS["text_dim"],
                         font=("Segoe UI", 9, "bold"),
                         borderwidth=0,
                         relief="flat")
        style.map("Treeview",
                   background=[("selected", COLORS["accent"])],
                   foreground=[("selected", COLORS["bg_dark"])])

        # Combobox
        style.configure("TCombobox",
                         fieldbackground=COLORS["bg_card"],
                         background=COLORS["bg_header"],
                         foreground=COLORS["text"],
                         arrowcolor=COLORS["accent"],
                         borderwidth=1,
                         relief="flat")
        style.map("TCombobox",
                   fieldbackground=[("readonly", COLORS["bg_card"])],
                   foreground=[("readonly", COLORS["text"])])

        # Scrollbar
        style.configure("Vertical.TScrollbar",
                         background=COLORS["bg_header"],
                         troughcolor=COLORS["bg_dark"],
                         borderwidth=0,
                         arrowcolor=COLORS["text_dim"])

        # Progressbar
        style.configure("Scan.Horizontal.TProgressbar",
                         background=COLORS["accent"],
                         troughcolor=COLORS["bg_header"],
                         borderwidth=0,
                         thickness=4)

    # ================================================================== #
    #  MENU BAR                                                           #
    # ================================================================== #

    def _build_menu(self):
        menubar = tk.Menu(self, bg=COLORS["bg_header"], fg=COLORS["text"],
                          activebackground=COLORS["accent"], activeforeground=COLORS["bg_dark"],
                          borderwidth=0)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_card"], fg=COLORS["text"],
                            activebackground=COLORS["accent"], activeforeground=COLORS["bg_dark"])
        file_menu.add_command(label="Save Report as HTML...", command=lambda: self._save_report("html"))
        file_menu.add_command(label="Save Report as JSON...", command=lambda: self._save_report("json"))
        file_menu.add_command(label="Save Report as TXT...", command=lambda: self._save_report("txt"))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        # Scan menu
        scan_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_card"], fg=COLORS["text"],
                            activebackground=COLORS["accent"], activeforeground=COLORS["bg_dark"])
        scan_menu.add_command(label="Start Scan", command=self._start_scan)
        scan_menu.add_command(label="Cancel Scan", command=self._cancel_scan)
        scan_menu.add_separator()
        scan_menu.add_command(label="Clear Results", command=self._clear_results)
        menubar.add_cascade(label="Scan", menu=scan_menu)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_card"], fg=COLORS["text"],
                            activebackground=COLORS["accent"], activeforeground=COLORS["bg_dark"])
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    # ================================================================== #
    #  TOP BAR — Target, Ports, Profile, Scan Button                     #
    # ================================================================== #

    def _build_top_bar(self):
        top = tk.Frame(self, bg=COLORS["bg_panel"], padx=12, pady=10)
        top.pack(fill=tk.X)

        # Row 1: Target + Profile + Scan button
        row1 = tk.Frame(top, bg=COLORS["bg_panel"])
        row1.pack(fill=tk.X, pady=(0, 6))

        # Target
        tk.Label(row1, text="Target:", font=("Segoe UI", 10, "bold"),
                 bg=COLORS["bg_panel"], fg=COLORS["accent"]).pack(side=tk.LEFT, padx=(0, 6))

        self.target_var = tk.StringVar(value="")
        self.target_entry = tk.Entry(
            row1,
            textvariable=self.target_var,
            font=("Consolas", 11),
            bg=COLORS["bg_card"],
            fg=COLORS["text_bright"],
            insertbackground=COLORS["accent"],
            relief=tk.FLAT,
            borderwidth=0,
            highlightthickness=1,
            highlightcolor=COLORS["accent"],
            highlightbackground=COLORS["border"],
        )
        self.target_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 12), ipady=4)
        self.target_entry.bind("<Return>", lambda e: self._start_scan())

        # Profile dropdown
        tk.Label(row1, text="Profile:", font=("Segoe UI", 10, "bold"),
                 bg=COLORS["bg_panel"], fg=COLORS["accent"]).pack(side=tk.LEFT, padx=(0, 6))

        self.profile_var = tk.StringVar(value="Quick Scan")
        profile_names = list(SCAN_PROFILES.keys())
        self.profile_combo = ttk.Combobox(
            row1,
            textvariable=self.profile_var,
            values=profile_names,
            state="readonly",
            font=("Segoe UI", 10),
            width=18,
        )
        self.profile_combo.pack(side=tk.LEFT, padx=(0, 12))
        self.profile_combo.bind("<<ComboboxSelected>>", lambda e: self._on_profile_change())

        # Scan button
        self.scan_btn = tk.Button(
            row1,
            text="⚡ Scan",
            font=("Segoe UI", 10, "bold"),
            bg=COLORS["green"],
            fg=COLORS["bg_dark"],
            activebackground="#2ea043",
            activeforeground=COLORS["bg_dark"],
            relief=tk.FLAT,
            padx=20,
            pady=3,
            cursor="hand2",
            command=self._start_scan,
        )
        self.scan_btn.pack(side=tk.LEFT)

        # Row 2: Ports
        row2 = tk.Frame(top, bg=COLORS["bg_panel"])
        row2.pack(fill=tk.X)

        tk.Label(row2, text="Ports:", font=("Segoe UI", 10, "bold"),
                 bg=COLORS["bg_panel"], fg=COLORS["accent"]).pack(side=tk.LEFT, padx=(0, 6))

        self.ports_var = tk.StringVar(value="top100")
        self.ports_entry = tk.Entry(
            row2,
            textvariable=self.ports_var,
            font=("Consolas", 10),
            bg=COLORS["bg_card"],
            fg=COLORS["text"],
            insertbackground=COLORS["accent"],
            relief=tk.FLAT,
            borderwidth=0,
            highlightthickness=1,
            highlightcolor=COLORS["accent"],
            highlightbackground=COLORS["border"],
            width=30,
        )
        self.ports_entry.pack(side=tk.LEFT, padx=(0, 12), ipady=3)

        # Profile description
        self.profile_desc = tk.Label(row2, text="", font=("Segoe UI", 9),
                                     bg=COLORS["bg_panel"], fg=COLORS["text_dim"], anchor="w")
        self.profile_desc.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._on_profile_change()

    # ================================================================== #
    #  COMMAND BAR — shows equivalent CLI command                        #
    # ================================================================== #

    def _build_command_bar(self):
        cmd_frame = tk.Frame(self, bg=COLORS["bg_header"], padx=12, pady=5)
        cmd_frame.pack(fill=tk.X)

        tk.Label(cmd_frame, text="Command:", font=("Segoe UI", 8, "bold"),
                 bg=COLORS["bg_header"], fg=COLORS["text_dim"]).pack(side=tk.LEFT, padx=(0, 6))

        self.command_var = tk.StringVar()
        self.command_entry = tk.Entry(
            cmd_frame,
            textvariable=self.command_var,
            font=("Consolas", 9),
            bg=COLORS["bg_card"],
            fg=COLORS["cyan"],
            insertbackground=COLORS["accent"],
            relief=tk.FLAT,
            borderwidth=0,
            highlightthickness=0,
            state="readonly",
            readonlybackground=COLORS["bg_card"],
        )
        self.command_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=3)

    # ================================================================== #
    #  NOTEBOOK — tabbed results                                          #
    # ================================================================== #

    def _build_notebook(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        # Tab 1: Scan Output
        self.output_view = ScanOutputView(self.notebook)
        self.notebook.add(self.output_view, text="  📋 Scan Output  ")

        # Tab 2: Ports/Hosts
        self.ports_view = PortsTableView(self.notebook)
        self.notebook.add(self.ports_view, text="  🔓 Ports / Hosts  ")

        # Tab 3: Host Details
        self.host_view = HostDetailsView(self.notebook)
        self.notebook.add(self.host_view, text="  🖥 Host Details  ")

        # Tab 4: Topology
        self.topology_view = TopologyView(self.notebook)
        self.notebook.add(self.topology_view, text="  🌐 Topology  ")

        # Welcome message on first launch
        self.output_view.append("=" * 60, "header")
        self.output_view.append("  StealthScan v1.1 — Graphical Interface", "header")
        self.output_view.append("  Zenmap-style network reconnaissance tool", "dim")
        self.output_view.append("=" * 60, "header")
        self.output_view.append("", "default")
        self.output_view.append("  Enter a target and click ⚡ Scan to begin.", "info")
        self.output_view.append("", "default")
        self.output_view.append("  Examples:", "dim")
        self.output_view.append("    • 192.168.1.1        (single host)", "dim")
        self.output_view.append("    • 192.168.1.0/24     (whole subnet)", "dim")
        self.output_view.append("    • scanme.nmap.org    (hostname)", "dim")
        self.output_view.append("", "default")
        self.output_view.append("  [!] Use ONLY on systems you own or have", "warning")
        self.output_view.append("      written permission to test.", "warning")

    # ================================================================== #
    #  STATUS BAR                                                         #
    # ================================================================== #

    def _build_status_bar(self):
        status = tk.Frame(self, bg=COLORS["bg_header"], padx=12, pady=5)
        status.pack(fill=tk.X, side=tk.BOTTOM)

        # Progress bar
        self.progress = ttk.Progressbar(status, style="Scan.Horizontal.TProgressbar",
                                         orient=tk.HORIZONTAL, mode="determinate", length=150)
        self.progress.pack(side=tk.LEFT, padx=(0, 10))

        # Status label
        self.status_label = tk.Label(status, text="Ready", font=("Segoe UI", 9),
                                     bg=COLORS["bg_header"], fg=COLORS["text_dim"], anchor="w")
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Timer
        self.timer_label = tk.Label(status, text="", font=("Consolas", 9),
                                    bg=COLORS["bg_header"], fg=COLORS["text_dim"])
        self.timer_label.pack(side=tk.RIGHT, padx=(10, 0))

        # Hosts/ports count
        self.count_label = tk.Label(status, text="", font=("Segoe UI", 9),
                                    bg=COLORS["bg_header"], fg=COLORS["accent"])
        self.count_label.pack(side=tk.RIGHT)

    # ================================================================== #
    #  PROFILE CHANGE                                                     #
    # ================================================================== #

    def _on_profile_change(self):
        name = self.profile_var.get()
        profile = SCAN_PROFILES.get(name, {})

        # Update ports field
        self.ports_var.set(profile.get("ports", "top100"))

        # Update description
        self.profile_desc.config(text=profile.get("description", ""))

        # Update command bar
        target = self.target_var.get() or "<target>"
        cmd = profile_to_command(target, name, profile, self.ports_var.get())
        self.command_var.set(cmd)

    # ================================================================== #
    #  SCAN START / CANCEL                                                #
    # ================================================================== #

    def _start_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            messagebox.showinfo("Scan Running", "A scan is already in progress. Cancel it first.")
            return

        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Please enter a target IP, hostname, or CIDR range.")
            self.target_entry.focus_set()
            return

        # Get profile settings
        profile_name = self.profile_var.get()
        profile = SCAN_PROFILES.get(profile_name, SCAN_PROFILES["Quick Scan"]).copy()
        ports_str = self.ports_var.get().strip() or "top100"

        # Update command display
        cmd = profile_to_command(target, profile_name, profile, ports_str)
        self.command_var.set(cmd)

        # Clear previous results
        self._clear_results()

        # Update UI for scanning state
        self.scan_btn.config(text="⛔ Cancel", bg=COLORS["red"], command=self._cancel_scan)
        self.status_label.config(text=f"Scanning {target}...", fg=COLORS["accent"])
        self.progress["value"] = 0

        # Start timer
        self._scan_start_time = datetime.now()
        self._update_timer()

        # Launch scan thread
        self._msg_queue = queue.Queue()
        self._scan_thread = ScanThread(target, ports_str, profile, self._msg_queue)
        self._scan_thread.start()

    def _cancel_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_thread.cancel()
            self.status_label.config(text="Cancelling scan...", fg=COLORS["yellow"])

    def _clear_results(self):
        self.output_view.clear()
        self.ports_view.clear()
        self.host_view.clear()
        self.topology_view.clear()
        self._scan_results = []
        self._scan_os_info = {}
        self.progress["value"] = 0
        self.count_label.config(text="")

    # ================================================================== #
    #  QUEUE POLLING — GUI thread reads messages from scan thread          #
    # ================================================================== #

    def _poll_queue(self):
        """Poll the message queue for scan results and update the GUI."""
        try:
            batch = 0
            while batch < 50:  # Process up to 50 messages per poll
                try:
                    msg_type, data = self._msg_queue.get_nowait()
                except queue.Empty:
                    break

                batch += 1

                if msg_type == MSG_LOG:
                    self.output_view.append(data["text"], data.get("tag", "default"))

                elif msg_type == MSG_RESULT:
                    # Avoid duplicates in the table
                    key = (data["host"], data["port"])
                    if key not in [(r["host"], r["port"]) for r in self._scan_results]:
                        self._scan_results.append(data)
                        self.ports_view.add_result(
                            data["host"], data["port"], data["state"],
                            data["service"], data["banner"], data.get("os_guess", ""),
                        )
                        self.host_view.add_host_port(
                            data["host"], data["port"], data["state"],
                            data["service"], data["banner"], data.get("os_guess", ""),
                        )
                        self.count_label.config(
                            text=f"{len(self._scan_results)} open port(s) found")

                elif msg_type == MSG_PROGRESS:
                    pct = data.get("percent", 0)
                    self.progress["value"] = pct
                    self.status_label.config(
                        text=f"Scanning... {data['current']}/{data['total']} probes ({pct}%)")

                elif msg_type == MSG_OS_INFO:
                    host = data["host"]
                    info = data["info"]
                    self._scan_os_info[host] = info
                    self.host_view.set_os_info(host, info)
                    os_name = info.get("os", "?") if isinstance(info, dict) else str(info)
                    # Update topology
                    port_count = len([r for r in self._scan_results if r["host"] == host])
                    self.topology_view.add_host(host, os_name, port_count)

                elif msg_type == MSG_COMPLETE:
                    self._on_scan_complete(data)

                elif msg_type == MSG_ERROR:
                    self.output_view.append(data["text"], "error")
                    self._on_scan_complete({"duration": "?", "open": 0, "total": 0})

        except Exception:
            pass

        # Schedule next poll
        self.after(80, self._poll_queue)

    # ================================================================== #
    #  SCAN COMPLETE                                                      #
    # ================================================================== #

    def _on_scan_complete(self, data):
        # Reset button
        self.scan_btn.config(text="⚡ Scan", bg=COLORS["green"], command=self._start_scan)
        self.progress["value"] = 100

        duration = data.get("duration", "?")
        open_count = data.get("open", len(self._scan_results))

        self.status_label.config(
            text=f"Scan complete — {open_count} open port(s) in {duration}",
            fg=COLORS["green"])

        # Stop timer
        self._scan_start_time = None

        # Update topology with all hosts
        if "os_info" in data:
            for host, info in data["os_info"].items():
                os_name = info.get("os", "?") if isinstance(info, dict) else str(info)
                port_count = len([r for r in self._scan_results if r["host"] == host])
                self.topology_view.add_host(host, os_name, port_count)
            # Also update any hosts without OS info
            all_hosts = set(r["host"] for r in self._scan_results)
            for host in all_hosts:
                if host not in data.get("os_info", {}):
                    port_count = len([r for r in self._scan_results if r["host"] == host])
                    self.topology_view.add_host(host, "Unknown", port_count)

    # ================================================================== #
    #  TIMER                                                              #
    # ================================================================== #

    def _update_timer(self):
        if self._scan_start_time:
            elapsed = datetime.now() - self._scan_start_time
            mins, secs = divmod(int(elapsed.total_seconds()), 60)
            self.timer_label.config(text=f"⏱ {mins:02d}:{secs:02d}")
            self._timer_id = self.after(1000, self._update_timer)
        else:
            if self._timer_id:
                self.after_cancel(self._timer_id)
                self._timer_id = None

    # ================================================================== #
    #  SAVE REPORT                                                        #
    # ================================================================== #

    def _save_report(self, fmt: str):
        if not self._scan_results:
            messagebox.showinfo("No Results", "Run a scan first before saving a report.")
            return

        ext_map = {"html": ".html", "json": ".json", "txt": ".txt"}
        ext = ext_map.get(fmt, ".txt")

        filepath = filedialog.asksaveasfilename(
            title=f"Save Report as {fmt.upper()}",
            defaultextension=ext,
            filetypes=[(f"{fmt.upper()} files", f"*{ext}"), ("All files", "*.*")],
            initialfile=f"stealth_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}",
        )
        if not filepath:
            return

        try:
            from core.reporter import Reporter
            from core.scanner import ScanResult

            # Reconstruct ScanResult objects
            results = []
            for r in self._scan_results:
                results.append(ScanResult(
                    host=r["host"],
                    port=int(r["port"]),
                    state=r["state"],
                    service=r.get("service", ""),
                    banner=r.get("banner", ""),
                    os_guess=r.get("os_guess", ""),
                ))

            meta = {
                "targets": [self.target_var.get()],
                "scan_type": SCAN_PROFILES.get(self.profile_var.get(), {}).get("scan_type", "connect"),
                "timing": SCAN_PROFILES.get(self.profile_var.get(), {}).get("timing", "normal"),
                "duration": self.status_label.cget("text").split("in ")[-1] if "in " in self.status_label.cget("text") else "?",
                "ports_probed": "?",
                "os_info": self._scan_os_info,
            }

            reporter = Reporter(results, meta)
            if fmt == "html":
                reporter.to_html(filepath)
            elif fmt == "json":
                reporter.to_json(filepath)
            else:
                reporter.to_txt(filepath)

            messagebox.showinfo("Saved", f"Report saved to:\n{filepath}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report:\n{e}")

    # ================================================================== #
    #  ABOUT                                                              #
    # ================================================================== #

    def _show_about(self):
        about = tk.Toplevel(self)
        about.title("About StealthScan")
        about.geometry("420x320")
        about.configure(bg=COLORS["bg_panel"])
        about.resizable(False, False)
        about.transient(self)
        about.grab_set()

        tk.Label(about, text="🔍 StealthScan", font=("Segoe UI", 18, "bold"),
                 bg=COLORS["bg_panel"], fg=COLORS["accent"]).pack(pady=(25, 5))
        tk.Label(about, text="v1.1 — Graphical Edition", font=("Segoe UI", 10),
                 bg=COLORS["bg_panel"], fg=COLORS["text_dim"]).pack()
        tk.Label(about, text="Python Network Reconnaissance Tool",
                 font=("Segoe UI", 10), bg=COLORS["bg_panel"], fg=COLORS["text"]).pack(pady=(15, 5))

        info_text = (
            "• TCP Connect / SYN Stealth / UDP scans\n"
            "• OS Fingerprinting (port-based + TTL)\n"
            "• Decoy injection & packet fragmentation\n"
            "• 6 timing profiles (paranoid → insane)\n"
            "• Banner grabbing & service detection\n"
            "• HTML / JSON / TXT reports"
        )
        tk.Label(about, text=info_text, font=("Segoe UI", 9),
                 bg=COLORS["bg_panel"], fg=COLORS["text"], justify=tk.LEFT).pack(pady=10)

        tk.Label(about, text="⚠️  For authorized penetration testing ONLY",
                 font=("Segoe UI", 9, "bold"), bg=COLORS["bg_panel"], fg=COLORS["yellow"]).pack(pady=(5, 5))

        tk.Label(about, text="MIT © MuneebKhattak-1", font=("Segoe UI", 8),
                 bg=COLORS["bg_panel"], fg=COLORS["text_dim"]).pack(pady=(5, 10))

        tk.Button(about, text="Close", font=("Segoe UI", 9), bg=COLORS["bg_card"],
                  fg=COLORS["text"], relief=tk.FLAT, padx=20, pady=4,
                  command=about.destroy, cursor="hand2").pack()

    # ================================================================== #
    #  RESIZE HANDLER                                                     #
    # ================================================================== #

    def _on_resize(self, event):
        """Redraw topology on window resize."""
        if hasattr(self, 'topology_view') and self.topology_view._hosts:
            self.topology_view._redraw()
