from datetime import datetime, time
import re

def preprocess_events(raw_events: list) -> list:
    cleaned = []
    seen = set()
    for evt in raw_events:
        eid = evt.get("id") or evt.get("event_id")
        if eid in seen:
            continue
        seen.add(eid)
        if not evt.get("event_type"):
            continue
        evt["timestamp"] = _normalize_timestamp(evt.get("timestamp"))
        evt["size"] = _normalize_size(evt.get("size"))
        evt["extension"] = _normalize_extension(evt.get("extension"))
        evt["folder"] = _normalize_folder(evt.get("folder"))
        cleaned.append(evt)
    return cleaned

def _normalize_timestamp(ts):
    if not ts:
        return datetime.utcnow().isoformat()
    if isinstance(ts, datetime):
        return ts.isoformat()
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).isoformat()
    except Exception:
        return datetime.utcnow().isoformat()

def _normalize_size(size):
    if not size:
        return None
    if isinstance(size, (int, float)):
        return f"{size / (1024*1024):.1f}MB"
    s = str(size).strip().upper()
    m = re.match(r"([0-9.]+)\s*(B|KB|MB|GB|TB)?", s)
    if not m:
        return s
    val, unit = float(m.group(1)), m.group(2) or "B"
    if unit == "KB":
        return f"{val/1024:.1f}MB"
    if unit == "GB":
        return f"{val*1024:.1f}MB"
    if unit == "TB":
        return f"{val*1024*1024:.1f}MB"
    if unit == "B":
        return f"{val/(1024*1024):.1f}MB"
    return s

def _normalize_extension(ext):
    if not ext:
        return None
    ext = ext.strip().lower()
    if not ext.startswith("."):
        ext = "." + ext
    return ext

def _normalize_folder(folder):
    if not folder:
        return None
    folder = folder.replace("\\", "/").strip("/")
    return folder or None
