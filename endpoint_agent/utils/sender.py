import requests
import json
from datetime import datetime

API_BASE_URL = "http://127.0.0.1:8000/api"

def send_event(event_data: dict):
    try:
        payload = {
            "employee_id": event_data.get("employee_id", 1),
            "timestamp": event_data.get("timestamp", datetime.utcnow().isoformat()),
            "event_type": event_data.get("event_type"),
            "filename": event_data.get("filename"),
            "extension": event_data.get("extension"),
            "size": event_data.get("size"),
            "folder": event_data.get("folder"),
            "usb_status": event_data.get("usb_status"),
            "network_upload": event_data.get("network_upload"),
            "cpu_usage": event_data.get("cpu_usage"),
            "ram_usage": event_data.get("ram_usage"),
            "details": event_data.get("details")
        }
        response = requests.post(f"{API_BASE_URL}/events", json=payload, timeout=5)
        return response.status_code == 200
    except Exception as e:
        print(f"Failed to send event: {e}")
        return False

def check_backend_health():
    try:
        response = requests.get(f"{API_BASE_URL}/status", timeout=2)
        return response.status_code == 200
    except Exception:
        return False
