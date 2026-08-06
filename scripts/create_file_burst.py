#!/usr/bin/env python3
"""
ThreatVista - Create a File Burst on the Desktop

Creates N (default 150) small files inside a fresh folder on the REAL desktop
(the OneDrive-redirected one when present), so the endpoint agent's file
monitor — which now watches OneDrive Desktop/Documents/Downloads — captures
them as `folder_create` + `file_create` events and the dashboard shows the
burst in real time.

Usage:
    python scripts/create_file_burst.py [count]

Run this on the same machine as the endpoint agent (the employee laptop), NOT
on the backend machine.
"""
import os
import sys
from datetime import datetime


def real_desktop():
    """Resolve the real Desktop (OneDrive-redirected preferred)."""
    base = os.path.expanduser("~")
    for cand in (os.path.join(base, "OneDrive", "Desktop"), os.path.join(base, "Desktop")):
        if os.path.isdir(cand):
            return cand
    return os.path.join(base, "Desktop")


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 150
    desktop = real_desktop()
    folder = os.path.join(desktop, "burst_" + datetime.now().strftime("%H%M%S"))
    os.makedirs(folder, exist_ok=True)
    for i in range(count):
        with open(os.path.join(folder, f"file_{i:03d}.txt"), "w") as fh:
            fh.write(f"demo file {i}\n")
    print(f"[+] Created {count} files in: {folder}")
    print(f"    The agent watches: {desktop}")
    print("    Open the ThreatVista dashboard and watch the Live Telemetry chart.")


if __name__ == "__main__":
    main()
