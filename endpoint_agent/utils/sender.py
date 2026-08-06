import os
import requests
import json
from datetime import datetime

def _resolve_api_base_url():
    """Backend API base URL, from BACKEND_URL if set (LAN demo) else localhost.

    Accepts either the full API root (http://host:8000/api) or just the server
    root (http://host:8000), appending "/api" as needed.
    """
    url = os.environ.get("BACKEND_URL", "http://127.0.0.1:8000/api").rstrip("/")
    if not url.endswith("/api"):
        url += "/api"
    return url

API_BASE_URL = _resolve_api_base_url()

# Optional shared secret. If the backend is configured with THREATVISTA_AGENT_KEY,
# events must carry the matching X-Agent-Key header.
AGENT_KEY = os.environ.get("THREATVISTA_AGENT_KEY", "")

def _headers():
    headers = {"Content-Type": "application/json"}
    if AGENT_KEY:
        headers["X-Agent-Key"] = AGENT_KEY
    return headers

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
        response = requests.post(f"{API_BASE_URL}/events", json=payload, headers=_headers(), timeout=5)
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


def register_device(employee_email: str, device_info: dict):
    """Register this machine's device for the employee.

    Returns ``(result, err)`` where ``result`` is the backend's full response
    dict (``{registered, employee_id, device_id}``) so the agent can attach the
    *correct* employee identity to every subsequent event.
    """
    payload = {"employee_email": employee_email, **device_info}
    try:
        response = requests.post(f"{API_BASE_URL}/agent/register", json=payload, headers=_headers(), timeout=10)
        if response.status_code == 200:
            return response.json(), None
        return None, response.json().get("detail", f"register failed ({response.status_code})")
    except Exception as exc:
        return None, str(exc)


def send_heartbeat(device_id: str, metrics: dict):
    """Send a heartbeat so the backend can mark the device online/offline."""
    payload = {"device_id": device_id, **metrics}
    try:
        response = requests.post(f"{API_BASE_URL}/agent/heartbeat", json=payload, headers=_headers(), timeout=10)
        return response.status_code == 200
    except Exception as exc:
        print(f"Failed to send heartbeat: {exc}")
        return False
