import os
import requests
import json
from datetime import datetime

def _normalize_url(raw_url: str) -> str:
    url = (raw_url or "").strip().rstrip("/")
    if not url:
        return "http://127.0.0.1:8000/api"
    if not (url.startswith("http://") or url.startswith("https://")):
        url = f"http://{url}"
    if not url.endswith("/api"):
        url += "/api"
    return url

def _resolve_api_base_url():
    """Backend API base URL, from BACKEND_URL if set (LAN demo) else localhost."""
    return _normalize_url(os.environ.get("BACKEND_URL", "http://127.0.0.1:8000/api"))

API_BASE_URL = _resolve_api_base_url()

def set_backend_url(raw_url: str) -> str:
    """Dynamically set or update the backend URL for all API calls."""
    global API_BASE_URL
    API_BASE_URL = _normalize_url(raw_url)
    os.environ["BACKEND_URL"] = get_backend_url()
    return API_BASE_URL

def get_backend_url() -> str:
    """Return backend base URL without the trailing /api."""
    return API_BASE_URL[:-4] if API_BASE_URL.endswith("/api") else API_BASE_URL

# Optional shared secret. If the backend is configured with THREATVISTA_AGENT_KEY,
# events must carry the matching X-Agent-Key header.
AGENT_KEY = os.environ.get("THREATVISTA_AGENT_KEY", "")

def _headers():
    headers = {"Content-Type": "application/json"}
    if AGENT_KEY:
        headers["X-Agent-Key"] = AGENT_KEY
    return headers

def _build_event_payload(event_data: dict) -> dict:
    return {
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
        "details": event_data.get("details"),
        "device_name": event_data.get("device_name"),
        "vendor_id": event_data.get("vendor_id"),
        "product_id": event_data.get("product_id"),
        "serial_number": event_data.get("serial_number"),
        "drive_letter": event_data.get("drive_letter"),
        "volume_name": event_data.get("volume_name"),
        "file_system": event_data.get("file_system"),
    }



def send_event(event_data: dict):
    try:
        payload = _build_event_payload(event_data)
        response = requests.post(f"{API_BASE_URL}/events", json=payload, headers=_headers(), timeout=5)
        return response.status_code == 200
    except Exception as e:
        print(f"Failed to send event: {e}")
        return False


def send_event_batch(events: list):
    """Send a whole agent batch as ONE bulk-ingest request.

    ``events`` is the raw list of telemetry dicts collected by the batcher; the
    backend inserts them all in a single transaction and broadcasts one
    consolidated WebSocket message.
    """
    try:
        payload = {"events": [_build_event_payload(evt) for evt in events]}
        response = requests.post(f"{API_BASE_URL}/events/batch", json=payload, headers=_headers(), timeout=10)
        return response.status_code == 200
    except Exception as e:
        print(f"Failed to send event batch ({len(events)} events): {e}")
        return False

def check_backend_health(target_url: str = None):
    url_to_test = _normalize_url(target_url) if target_url else API_BASE_URL
    try:
        response = requests.get(f"{url_to_test}/status", timeout=3)
        return response.status_code == 200
    except Exception:
        return False


def register_device_with_token(enrollment_token: str, device_info: dict):
    """Register this machine's device using a one-time enrollment token.

    Returns ``(result, err)`` where ``result`` is the backend's full response
    dict (``{registered, employee_id, device_id, employee_name}``) so the agent
    can attach the *correct* employee identity to every subsequent event. The
    backend validates the token (10-min expiry, single use) and consumes it.
    """
    payload = {"enrollment_token": enrollment_token, **device_info}
    try:
        response = requests.post(f"{API_BASE_URL}/agent/register", json=payload, headers=_headers(), timeout=10)
        if response.status_code == 200:
            return response.json(), None
        return None, response.json().get("detail", f"register failed ({response.status_code})")
    except Exception as exc:
        return None, str(exc)


def register_device(employee_email: str, device_info: dict):
    """Legacy email-based registration (kept for already-installed agents).

    Returns ``(result, err)`` like ``register_device_with_token``.
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
    """Send a heartbeat so the backend can mark the device online/offline.

    Returns the full JSON response dict (which includes pending commands) on
    success, or None on failure.
    """
    payload = {"device_id": device_id, **metrics}
    try:
        response = requests.post(f"{API_BASE_URL}/agent/heartbeat", json=payload, headers=_headers(), timeout=10)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as exc:
        print(f"Failed to send heartbeat: {exc}")
        return None
