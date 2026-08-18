"""Enrollment helpers for the ThreatVista endpoint agent.

Two local files matter:

* ``threatvista-agent-config.json`` — downloaded from the employee profile page
  when the employee clicks "Connect This Device". Holds the one-time enrollment
  token plus the backend URL. Deleted after a successful registration so the
  token can never be reused.

* ``threatvista-agent-device.json`` — written after the first successful
  registration. Persists the resolved device/employee identity so a later run of
  the agent reconnects to the SAME device (no duplicate, no re-enrollment) and
  simply resumes heartbeats + monitoring.
"""
import json
import os

CONFIG_FILENAME = "threatvista-agent-config.json"
DEVICE_FILENAME = "threatvista-agent-device.json"


def _candidate_dirs():
    """Directories to search for the enrollment/device files, in order."""
    dirs = [
        os.getcwd(),                                              # project root via start_agent.bat
        os.path.dirname(os.path.abspath(__file__)),               # endpoint_agent/utils/
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),  # project root
        os.path.join(os.path.expanduser("~"), "Downloads"),       # where browsers drop the file
    ]
    seen = set()
    out = []
    for d in dirs:
        d = os.path.normpath(d)
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _find_file(filename):
    for d in _candidate_dirs():
        path = os.path.join(d, filename)
        if os.path.isfile(path):
            return path
    return None


def load_enrollment_config():
    """Read ``threatvista-agent-config.json`` -> {token, backend_url, path}."""
    path = _find_file(CONFIG_FILENAME)
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        token = (data.get("token") or "").strip()
        backend_url = (data.get("backend_url") or "").strip().rstrip("/")
        if not token or not backend_url:
            print(f"[!] {CONFIG_FILENAME} at {path} is missing token/backend_url")
            return None
        return {"token": token, "backend_url": backend_url, "path": path}
    except Exception as exc:
        print(f"[!] Could not read {CONFIG_FILENAME}: {exc}")
        return None


def delete_enrollment_config(cfg):
    """Remove the config file now that its token has been consumed."""
    try:
        os.remove(cfg["path"])
        print(f"[+] Removed {CONFIG_FILENAME} (token used, no longer needed)")
    except Exception as exc:
        print(f"[!] Could not remove {CONFIG_FILENAME}: {exc}")


def load_device_identity():
    """Read ``threatvista-agent-device.json`` -> {device_id, employee_id, ...}."""
    path = _find_file(DEVICE_FILENAME)
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not data.get("device_id") or not data.get("employee_id"):
            return None
        return data
    except Exception as exc:
        print(f"[!] Could not read {DEVICE_FILENAME}: {exc}")
        return None


def save_device_identity(identity):
    """Persist the resolved identity so future runs reconnect to the same device."""
    # Keep it at the project root (first candidate dir) so it is always found.
    path = os.path.join(_candidate_dirs()[0], DEVICE_FILENAME)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(identity, fh, indent=2)
        print(f"[+] Saved device identity to {path}")
    except Exception as exc:
        print(f"[!] Could not save {DEVICE_FILENAME}: {exc}")


def update_device_backend_url(new_url: str):
    """Update backend_url in threatvista-agent-device.json so next runs connect automatically."""
    identity = load_device_identity()
    if identity:
        identity["backend_url"] = (new_url or "").strip().rstrip("/")
        save_device_identity(identity)
        return True
    return False
