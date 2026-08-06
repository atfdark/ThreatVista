from datetime import datetime, timedelta
from typing import Dict, List, Optional
import numpy as np
from collections import defaultdict

class BehaviorDNA:
    def __init__(self):
        self.baselines: Dict[int, dict] = {}

    def compute_baseline(self, employee_id: int, events: list) -> dict:
        if not events:
            return self._empty_baseline(employee_id)
        now = datetime.utcnow()
        window_7d = [e for e in events if _within_days(e.get("timestamp"), now, 7)]
        window_30d = [e for e in events if _within_days(e.get("timestamp"), now, 30)]

        login_hours = []
        usb_inserts = 0
        file_copies = 0
        upload_mb = 0.0
        process_starts = 0
        night_count = 0
        weekend_count = 0
        cpu_vals = []
        ram_vals = []

        for e in window_30d:
            if e.get("event_type") == "login" and e.get("timestamp"):
                try:
                    t = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
                    login_hours.append(t.hour)
                    if t.hour < 6 or t.hour >= 22:
                        night_count += 1
                    if t.weekday() >= 5:
                        weekend_count += 1
                except Exception:
                    pass
            if e.get("event_type") == "usb_insert":
                usb_inserts += 1
            if e.get("event_type") in ("file_copy", "file_create", "file_modify"):
                file_copies += 1
            if e.get("event_type") == "network_upload":
                v = _parse_mb(e.get("network_upload"))
                if v is not None:
                    upload_mb += v
            if e.get("event_type") == "process_start":
                process_starts += 1
            if e.get("cpu_usage") is not None:
                try:
                    cpu_vals.append(float(e["cpu_usage"]))
                except Exception:
                    pass
            if e.get("ram_usage") is not None:
                try:
                    ram_vals.append(float(e["ram_usage"]))
                except Exception:
                    pass

        # Use observed day span (clamped to 1–30) so brand-new employees show
        # meaningful per-day averages instead of everything diluted by /30.
        days = _observed_days(window_30d, now)

        baseline = {
            "employee_id": employee_id,
            "working_hours_baseline": _working_hours_str(login_hours),
            "avg_usb_inserts_per_day": round(usb_inserts / days, 2) if window_30d else 0,
            "avg_file_copies_per_day": round(file_copies / days, 2) if window_30d else 0,
            "avg_upload_mb_per_day": round(upload_mb / days, 2) if window_30d else 0,
            "avg_process_starts_per_day": round(process_starts / days, 2) if window_30d else 0,
            "avg_cpu_usage": float(np.mean(cpu_vals)) if cpu_vals else 0,
            "avg_ram_usage": float(np.mean(ram_vals)) if ram_vals else 0,
            "night_activity_rate": night_count / max(len(window_30d), 1),
            "weekend_activity_rate": weekend_count / max(len(window_30d), 1),
            "updated_at": datetime.utcnow().isoformat()
        }
        self.baselines[employee_id] = baseline
        return baseline

    def get_baseline(self, employee_id: int) -> dict:
        return self.baselines.get(employee_id, self._empty_baseline(employee_id))

    def deviation_scores(self, features: dict, baseline: dict) -> dict:
        scores = {}
        scores["usb_deviation"] = _safe_div(features.get("usb_inserts_24h", 0), max(baseline.get("avg_usb_inserts_per_day", 0), 1e-6))
        scores["copy_deviation"] = _safe_div(features.get("files_copied_24h", 0), max(baseline.get("avg_file_copies_per_day", 1), 1))
        scores["upload_deviation"] = _safe_div(features.get("network_upload_mb_24h", 0), max(baseline.get("avg_upload_mb_per_day", 1), 1))
        scores["cpu_deviation"] = _safe_div(features.get("avg_cpu_usage", 0), max(baseline.get("avg_cpu_usage", 1), 1))
        scores["ram_deviation"] = _safe_div(features.get("avg_ram_usage", 0), max(baseline.get("avg_ram_usage", 1), 1))
        scores["process_deviation"] = _safe_div(features.get("process_starts_24h", 0), max(baseline.get("avg_process_starts_per_day", 1), 1))
        return scores

    def _empty_baseline(self, employee_id: int) -> dict:
        return {
            "employee_id": employee_id,
            "working_hours_baseline": "09:00 - 17:00",
            "avg_usb_inserts_per_day": 0.0,
            "avg_file_copies_per_day": 0.0,
            "avg_upload_mb_per_day": 0.0,
            "avg_process_starts_per_day": 0.0,
            "avg_cpu_usage": 0.0,
            "avg_ram_usage": 0.0,
            "night_activity_rate": 0.0,
            "weekend_activity_rate": 0.0,
            "updated_at": datetime.utcnow().isoformat()
        }

def _within_days(ts, now, days):
    if not ts:
        return False
    try:
        t = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
        return (now - t).total_seconds() <= days * 86400
    except Exception:
        return False

def _observed_days(events, now):
    """Return 1–30 based on the oldest event in the window."""
    if not events:
        return 1.0
    oldest = None
    for e in events:
        ts = e.get("timestamp")
        if not ts:
            continue
        try:
            t = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
            if oldest is None or t < oldest:
                oldest = t
        except Exception:
            continue
    if oldest is None:
        return 1.0
    span = max(1.0, (now - oldest).total_seconds() / 86400.0)
    return min(30.0, span)

def _parse_mb(val):
    if val is None:
        return None
    s = str(val).strip().upper()
    import re
    m = re.match(r"([0-9.]+)\s*(MB|GB|KB|B|TB)?", s)
    if not m:
        return None
    v, u = float(m.group(1)), m.group(2) or "B"
    if u == "GB": return v * 1024
    if u == "KB": return v / 1024
    if u == "TB": return v * 1024 * 1024
    if u == "B": return v / (1024 * 1024)
    return v

def _working_hours_str(hours):
    if not hours:
        return "09:00 - 17:00"
    h = np.median(hours)
    start = max(0, int(h - 2))
    end = min(23, int(h + 2))
    return f"{start:02d}:00 - {end:02d}:00"

def _safe_div(a, b):
    try:
        return float(a) / float(b)
    except Exception:
        return 0.0
