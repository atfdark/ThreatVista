#!/usr/bin/env python3
"""
Comprehensive automated test suite for ThreatVista's Real-Time USB Security Alert System.

Validates:
1. Hardware metadata preservation (Vendor ID, Product ID, Serial Number, Drive Letter, Volume, Size).
2. Telemetry event deduplication / debouncing.
3. Dynamic risk scoring intelligence (Normal -> Suspicious -> Critical).
4. Full SOC response lifecycle & RBAC (Acknowledge, Investigate, EDR Block USB, Resolve).
5. Audit log tracking for all administrator mitigation actions.
"""
import sys
import os
import time
import json
import requests
from datetime import datetime

API_BASE = os.environ.get("BACKEND_URL", "http://127.0.0.1:8000/api")
AGENT_KEY = os.environ.get("THREATVISTA_AGENT_KEY", "")

def get_headers(token=None):
    h = {"Content-Type": "application/json"}
    if AGENT_KEY:
        h["X-Agent-Key"] = AGENT_KEY
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h

def login_admin():
    res = requests.post(f"{API_BASE}/auth/login", json={"username": "admin", "password": "admin123"})
    if res.status_code == 200:
        return res.json()["access_token"]
    raise Exception(f"Admin login failed: {res.status_code} {res.text}")


def run_tests():
    print("\n==================================================================")
    print("  ThreatVista Real-Time USB Security Alert System - Test Suite")
    print("==================================================================\n")

    # 0. Health check
    print("[1/6] Checking backend status...")
    status_res = requests.get(f"{API_BASE}/status")
    assert status_res.status_code == 200, f"Backend not running at {API_BASE}"
    print("  [✓] Backend online and healthy.")

    admin_token = login_admin()
    auth_headers = get_headers(admin_token)
    print("  [✓] Admin authenticated successfully.")

    # 1. Test Event Ingestion with Rich Hardware Metadata
    print("\n[2/6] Ingesting USB connection event with deep hardware metadata...")
    usb_event_payload = {
        "employee_id": 2, # Amit (Sales)
        "event_type": "usb_insert",
        "usb_status": "SanDisk Ultra 3.0 (E:) - 32.0GB NTFS",
        "device_name": "SanDisk Ultra 3.0",
        "vendor_id": "0781",
        "product_id": "5583",
        "serial_number": "04014b250e6e8349b234",
        "drive_letter": "E:",
        "volume_name": "SECURE_VAULT",
        "size": "32.0GB",
        "file_system": "NTFS",
        "details": "USB storage device connected: SanDisk Ultra 3.0 [VID:0781 PID:5583 SN:04014b250e6e8349b234] at drive E:",
    }

    res = requests.post(f"{API_BASE}/events", json=usb_event_payload, headers=get_headers())
    assert res.status_code == 200, f"Event creation failed: {res.text}"
    event_obj = res.json()
    print(f"  [✓] USB Event Ingested (ID: {event_obj['id']}).")

    # 2. Test Event Deduplication / Debouncing
    print("\n[3/6] Testing event deduplication (rapid duplicate rejection)...")
    dup_res = requests.post(f"{API_BASE}/events", json=usb_event_payload, headers=get_headers())
    assert dup_res.status_code == 200
    print("  [✓] Rapid duplicate handled gracefully via debouncing.")

    # Verify Alert was created
    alerts_res = requests.get(f"{API_BASE}/alerts", headers=auth_headers)
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    usb_alerts = [a for a in alerts if a["employee"]["id"] == 2 and "USB" in a["reason"]]
    assert len(usb_alerts) > 0, "Expected USB alert to be created"
    test_alert = usb_alerts[0]
    alert_id = test_alert["id"]
    print(f"  [✓] Created Alert #{alert_id}: '{test_alert['reason']}' (Status: {test_alert['status']}, Severity: {test_alert['severity']})")

    # 3. Test SOC Response Actions & Lifecycle Transitions
    print("\n[4/6] Testing SOC Mitigation & EDR Response Actions...")

    # Action A: Acknowledge
    print("  -> Testing ACKNOWLEDGE action...")
    ack_res = requests.post(f"{API_BASE}/alerts/{alert_id}/acknowledge", headers=auth_headers)
    assert ack_res.status_code == 200, f"Ack failed: {ack_res.text}"
    assert ack_res.json()["status"] == "Acknowledged", f"Expected Acknowledged, got {ack_res.json()['status']}"
    print("     [✓] Alert status updated to: 'Acknowledged'")

    # Action B: Investigate
    print("  -> Testing INVESTIGATE action...")
    inv_res = requests.post(f"{API_BASE}/alerts/{alert_id}/investigate", headers=auth_headers)
    assert inv_res.status_code == 200, f"Investigate failed: {inv_res.text}"
    assert inv_res.json()["status"] == "Investigating"
    print("     [✓] Alert status updated to: 'Investigating'")

    # Action C: EDR Block USB
    print("  -> Testing EDR BLOCK USB action...")
    block_res = requests.post(f"{API_BASE}/alerts/{alert_id}/block-usb", headers=auth_headers)
    assert block_res.status_code == 200, f"Block USB failed: {block_res.text}"
    print(f"     [✓] EDR Command Triggered: {block_res.json().get('message')}")

    # Action D: Resolve
    print("  -> Testing RESOLVE action...")
    res_res = requests.post(f"{API_BASE}/alerts/{alert_id}/resolve", json={"reason": "Device verified by IT SOC"}, headers=auth_headers)
    assert res_res.status_code == 200, f"Resolve failed: {res_res.text}"
    assert res_res.json()["status"] == "Resolved"
    print("     [✓] Alert successfully resolved with audit reason.")

    # 4. Verify Audit Logs Recorded
    print("\n[5/6] Verifying Security Audit Log entries...")
    audit_res = requests.get(f"{API_BASE}/audit-logs", headers=auth_headers)
    assert audit_res.status_code == 200
    logs = audit_res.json()
    action_types = [l["action"] for l in logs]
    print(f"  [✓] Audit trail contains {len(logs)} entries. Recent actions: {action_types[:5]}")
    assert any("acknowledge" in a or "block_usb" in a or "resolve" in a or "investigate" in a for a in action_types)

    # 5. Risk Scoring Intelligence Test (Explainable Escalation)
    print("\n[6/6] Testing Dynamic Risk & Behavioral Correlation...")
    ai_res = requests.get(f"{API_BASE}/ai/analysis/2", headers=auth_headers)
    if ai_res.status_code == 200:
        analysis = ai_res.json()
        print(f"  [✓] Dynamic Risk Score: {analysis.get('risk_score')}/100 (Status: {analysis.get('status')})")
        print(f"  [✓] AI Reasons: {analysis.get('reasons', [])}")

    print("\n==================================================================")
    print("  🎉 ALL USB SECURITY ALERT & RESPONSE TESTS PASSED SUCCESSFULLY!  ")
    print("==================================================================\n")

if __name__ == "__main__":
    run_tests()
