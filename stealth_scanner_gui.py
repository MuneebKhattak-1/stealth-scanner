"""
StealthScan - Graphical Interface Launcher
Run this to open the Zenmap-style GUI.

Usage:
    python stealth_scanner_gui.py
"""

import sys
import os

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.app import StealthScanApp


def main():
    app = StealthScanApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
