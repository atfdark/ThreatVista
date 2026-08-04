#!/usr/bin/env python3
"""
ThreatVista - Hackathon Demo Scenarios

Replays the four judge-facing scenarios against a running backend by injecting
real telemetry events through the API and then running the AI pipeline to show
how risk scores escalate (or stay safe).

Usage:
    python scripts/demo_scenarios.py

Requires the backend to be running on http://127.0.0.1:8000/api
"""
import sys
import time
import json
import urllib.request
from datetime import datetime, timedelta, timezone

API = "http://127.0.0.1:8000/api"

# Scenario targets: employee 1 = Rahul (Engineering), 2 = Amit (Sales),
#                   3 = Priya (HR)
SCENARIOS = [
    {
        "name": "Scenario 1 - Normal Employee",
        "employee_id": 3,
        "description": "Login at 9 AM, edit documents, logout. Expect SAFE.",
        "events": [
            {"event_type": "login", "details": "Logged in at 09:02 AM", "timestamp": "ist:9:2"},
            {"event_type": "file_modify", "filename": "performance_evaluation_Q2.docx", "extension": ".docx", "folder": "HR/Reviews", "size": "1.2MB", "details": "Edited Q2 performance review", "timestamp": "ist:10:30"},
            {"event_type": "file_modify", "filename": "attendance_sheet.xlsx", "extension": ".xlsx", "folder": "HR", "size": "0.4MB", "details": "Updated attendance sheet", "timestamp": "ist:12:0"},
            {"event_type": "file_create", "filename": "policy_draft_v3.docx", "extension": ".docx", "folder": "HR/Policies", "size": "0.8MB", "details": "Created new policy draft", "timestamp": "ist:16:30"},
        ],
    },
    {
        "name": "Scenario 2 - USB Activity",
        "employee_id": 2,
        "description": "Insert USB, copy a handful of files. Expect MEDIUM.",
        "events": [
            {"event_type": "usb_insert", "usb_status": "SanDisk 16GB", "details": "USB mass storage connected", "timestamp": "ist:22:30"},
            {"event_type": "file_copy", "filename": "q3_sales_report.xlsx", "extension": ".xlsx", "folder": "Sales", "size": "2.1MB", "details": "Copied report to USB", "timestamp": "ist:22:35"},
            {"event_type": "file_copy", "filename": "client_list.csv", "extension": ".csv", "folder": "Sales", "size": "0.9MB", "details": "Copied client list to USB", "timestamp": "ist:22:40"},
            {"event_type": "file_copy", "filename": "pipeline_forecast.xlsx", "extension": ".xlsx", "folder": "Sales", "size": "3.4MB", "details": "Copied forecast to USB", "timestamp": "ist:22:45"},
            {"event_type": "file_copy", "filename": "invoice_archive.zip", "extension": ".zip", "folder": "Sales/Archive", "size": "5.2MB", "details": "Copied archive to USB", "timestamp": "ist:22:50"},
            {"event_type": "file_copy", "filename": "partner_contacts.csv", "extension": ".csv", "folder": "Sales", "size": "0.7MB", "details": "Copied contacts to USB", "timestamp": "ist:22:55"},
        ],
    },
    {
        "name": "Scenario 3 - Insider Threat",
        "employee_id": 1,
        "description": "Midnight login, USB insert, mass copy 700 files, compress, upload. Expect CRITICAL.",
        "events": [
            {"event_type": "login", "details": "Login at 12:30 AM (outside working hours)", "timestamp": "ist:0:30"},
            {"event_type": "usb_insert", "usb_status": "Kingston 128GB", "details": "USB mass storage connected at night", "timestamp": "ist:1:0"},
            # Mass copy burst — enough events to exceed the 100-file threshold
            *[{"event_type": "file_copy", "filename": f"patent_design_{i:03d}.dwg", "extension": ".dwg", "folder": "Engineering/Patents", "size": "8.5MB", "details": "Mass copy of patent designs to USB", "timestamp": "ist:1:30"} for i in range(150)],
            {"event_type": "process_start", "details": "Spawned winrar.exe to compress copied files", "timestamp": "ist:2:0"},
            {"event_type": "network_upload", "network_upload": "2GB", "details": "Uploaded 2 GB archive to unknown external IP", "cpu_usage": 87.4, "ram_usage": 74.2, "timestamp": "ist:2:15"},
        ],
    },
    {
        "name": "Scenario 4 - Cover-Up Attempt",
        "employee_id": 2,
        "description": "Delete evidence files, remove USB, wipe temp files. Expect HIGH / CRITICAL.",
        "events": [
            {"event_type": "file_delete", "filename": "client_list.csv", "extension": ".csv", "folder": "Sales", "details": "Deleted copied client list", "timestamp": "ist:23:0"},
            {"event_type": "file_delete", "filename": "invoice_archive.zip", "extension": ".zip", "folder": "Sales/Archive", "details": "Deleted copied archive", "timestamp": "ist:23:5"},
            {"event_type": "usb_remove", "usb_status": "SanDisk 16GB", "details": "USB removed immediately after deletions", "timestamp": "ist:23:10"},
            {"event_type": "file_delete", "filename": "tmp_data_encryption.cache", "extension": ".cache", "folder": "Temp", "details": "Deleted temporary encryption artifacts", "timestamp": "ist:23:15"},
            {"event_type": "file_delete", "filename": "recycle_history.log", "extension": ".log", "folder": "Temp", "details": "Deleted history logs", "timestamp": "ist:23:20"},
            {"event_type": "process_start", "details": "Ran cipher.exe /w to wipe free space", "timestamp": "ist:23:30"},
        ],
    },
]


IST_OFFSET = timedelta(hours=5, minutes=30)


def _ist_ts(hour, minute=0, day_offset=0):
    """Return a UTC-naive ISO timestamp for the given IST clock time.

    The AI engine classifies night/working-hours in IST, and the database stores
    UTC. We subtract the IST offset so the stored timestamp maps back to the
    intended local clock time.
    """
    now_utc = datetime.now(timezone.utc)
    now_ist = now_utc + IST_OFFSET
    target = now_ist.replace(hour=hour, minute=minute, second=0, microsecond=0) + timedelta(days=day_offset)
    if target > now_ist:
        target -= timedelta(days=1)  # never stamp events in the future
    utc_aware = target - IST_OFFSET
    return utc_aware.replace(tzinfo=None).strftime("%Y-%m-%dT%H:%M:%S")


def _ts(marker):
    """Resolve an event timestamp marker to an ISO timestamp."""
    if marker.startswith("ist:"):
        parts = marker[4:].split(":")
        return _ist_ts(int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
    if marker == "now":
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    if marker.startswith("now-"):
        amount, unit = marker[4:-1], marker[-1]
        seconds = int(amount) * (3600 if unit == "h" else 60)
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - seconds))
    return marker


def post_event(token, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{API}/events",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"    [!] event POST failed: {e}")
        return None


def analyze(token, employee_id):
    req = urllib.request.Request(f"{API}/ai/analysis/{employee_id}")
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"    [!] analysis failed: {e}")
        return None


def login():
    body = json.dumps({"username": "admin", "password": "admin123"}).encode()
    req = urllib.request.Request(
        f"{API}/auth/login",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["access_token"]


def status_color(status):
    return {
        "Safe": "\033[92m",      # green
        "Medium": "\033[93m",    # yellow
        "High": "\033[91m",      # red
        "Critical": "\033[95m",  # magenta
    }.get(status, "")


def main():
    print("=" * 72)
    print("  ThreatVista - Hackathon Demo Scenario Replay")
    print("=" * 72)

    try:
        token = login()
        print("[+] Authenticated as admin.")
    except Exception as e:
        print(f"[!] Could not reach backend at {API}. Is it running?")
        print(f"    {e}")
        sys.exit(1)

    for scenario in SCENARIOS:
        print("\n" + "-" * 72)
        print(f"  {scenario['name']}")
        print(f"  {scenario['description']}")
        print("-" * 72)

        count = 0
        for ev in scenario["events"]:
            payload = {
                "employee_id": scenario["employee_id"],
                "event_type": ev["event_type"],
                "timestamp": _ts(ev.get("timestamp", "now")),
            }
            for key in ("filename", "extension", "size", "folder", "usb_status",
                        "network_upload", "cpu_usage", "ram_usage", "details"):
                if ev.get(key) is not None:
                    payload[key] = ev[key]
            created = post_event(token, payload)
            if created:
                count += 1
            time.sleep(0.02)  # let the feed breathe during the live demo

        print(f"    Injected {count} events.")
        result = analyze(token, scenario["employee_id"])
        if not result:
            continue

        color = status_color(result["status"])
        print(f"    Risk Score : {color}{result['risk_score']:.0f}\033[0m / 100")
        print(f"    Status     : {color}{result['status']}\033[0m")
        print("    Why:")
        for reason in result.get("reasons", [])[:5]:
            print(f"      - {reason}")
        if result.get("model_anomaly"):
            print("      - AI Isolation Forest flagged behavioral anomaly")

    print("\n" + "=" * 72)
    print("  Demo complete. Open the dashboard to watch alerts in real time.")
    print("=" * 72)


if __name__ == "__main__":
    main()
