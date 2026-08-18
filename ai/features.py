import math
from datetime import datetime, time, timedelta
from collections import defaultdict
from ai.role_config import get_role_config
from ai.sensitive_scanner import SensitiveAssetScanner

# Timezone offset (hours) applied to UTC timestamps before computing
# hour-of-day / day-of-week features. Set to +5.5 for IST (the demo narrative
# runs in Indian working hours). Adjust for other regions.
TIMEZONE_OFFSET_HOURS = 5.5

def _localize(ts):
    """Parse a timestamp string to a naive datetime shifted into local time."""
    if not ts:
        return None
    try:
        t = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
        return t + timedelta(hours=TIMEZONE_OFFSET_HOURS)
    except Exception:
        return None

SOURCE_CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".cpp", ".c", ".h", ".hpp", ".java",
    ".go", ".rs", ".cs", ".php", ".rb", ".html", ".css", ".scss", ".json",
    ".sql", ".sh", ".bash", ".bat", ".ps1", ".yaml", ".yml", ".xml", ".env"
}

ZIP_EXTENSIONS = {
    ".zip", ".tar", ".gz", ".7z", ".rar", ".bz2", ".xz", ".tgz"
}

OFFICE_EXTENSIONS = {
    ".docx", ".doc", ".xlsx", ".xls", ".csv", ".pptx", ".ppt", ".pdf", ".txt", ".rtf"
}

def engineer_features(events: list, employee_id: int, role_type: str = "General", db=None) -> dict:
    role_cfg = get_role_config(role_type)
    if not events:
        return _zero_features(employee_id, role_type, role_cfg)

    now = datetime.utcnow()
    window_24h = [e for e in events if _within_hours(e.get("timestamp"), now, 24)]
    window_1h = [e for e in events if _within_hours(e.get("timestamp"), now, 1)]

    files_copied_1h = _file_op_count(window_1h)
    files_copied_24h = _file_op_count(window_24h)
    files_created_24h = sum(1 for e in window_24h if e.get("event_type") == "file_create")
    files_modified_24h = sum(1 for e in window_24h if e.get("event_type") == "file_modify")
    
    usb_inserts_24h = sum(1 for e in window_24h if e.get("event_type") == "usb_insert")
    
    # Sensitive asset scanner analysis
    sensitive_scan = SensitiveAssetScanner.scan_events(window_24h, db=db)
    sensitive_files_24h = sensitive_scan["total_sensitive_events"]
    sensitive_matches = sensitive_scan["matches"]
    top_matched_keywords = sensitive_scan["top_matched_keywords"]
    sensitive_zip_count = sensitive_scan["sensitive_zip_count"]
    sensitive_max_risk = sensitive_scan["max_risk_added"]

    source_code_files_24h = _category_file_count(window_24h, SOURCE_CODE_EXTENSIONS, keywords=["source_code", "src", "repo", "git"])
    zip_files_24h = _category_file_count(window_24h, ZIP_EXTENSIONS, keywords=["archive", "backup", ".zip", ".tar"])
    office_files_24h = _category_file_count(window_24h, OFFICE_EXTENSIONS, keywords=["doc", "sheet", "report", "presentation"])

    network_uploads_24h = _sum_upload_mb(window_24h)
    login_hour = _get_login_hour(window_24h)
    weekend_activity = _has_weekend_activity(window_24h)
    night_activity = _has_night_activity(window_24h)
    folder_access_counts = _folder_counts(window_24h)
    delete_freq = sum(1 for e in window_24h if e.get("event_type") == "file_delete")
    rename_freq = sum(1 for e in window_24h if e.get("event_type") in ("file_rename", "file_move"))
    avg_cpu = _avg_metric(window_24h, "cpu_usage")
    avg_ram = _avg_metric(window_24h, "ram_usage")
    avg_file_size = _avg_file_size_mb(window_24h)
    process_starts = sum(1 for e in window_24h if e.get("event_type") == "process_start")
    process_stops = sum(1 for e in window_24h if e.get("event_type") == "process_stop")

    return {
        "employee_id": employee_id,
        "role_type": role_type,
        "role_config": role_cfg,
        "files_copied_per_hour": files_copied_1h,
        "files_copied_24h": files_copied_24h,
        "files_created_24h": files_created_24h,
        "files_modified_24h": files_modified_24h,
        "source_code_files_24h": source_code_files_24h,
        "zip_files_24h": zip_files_24h,
        "office_files_24h": office_files_24h,
        "usb_inserts_24h": usb_inserts_24h,
        "sensitive_files_24h": sensitive_files_24h,
        "sensitive_matches": sensitive_matches,
        "top_matched_keywords": top_matched_keywords,
        "sensitive_zip_count": sensitive_zip_count,
        "sensitive_max_risk": sensitive_max_risk,
        "network_upload_mb_24h": network_uploads_24h,
        "login_hour": login_hour if login_hour is not None else 12,
        "weekend_activity": 1 if weekend_activity else 0,
        "night_activity": 1 if night_activity else 0,
        "top_folder_access": _top_folder(folder_access_counts),
        "folder_access_count": len(folder_access_counts),
        "delete_freq_24h": delete_freq,
        "rename_freq_24h": rename_freq,
        "avg_cpu_usage": avg_cpu,
        "avg_ram_usage": avg_ram,
        "avg_file_size_mb": avg_file_size,
        "process_starts_24h": process_starts,
        "process_stops_24h": process_stops,
        "event_count_24h": len(window_24h),
        "event_count_1h": len(window_1h)
    }

def _zero_features(employee_id: int, role_type: str = "General", role_cfg: dict = None) -> dict:
    if role_cfg is None:
        role_cfg = get_role_config(role_type)
    return {
        "employee_id": employee_id,
        "role_type": role_type,
        "role_config": role_cfg,
        "files_copied_per_hour": 0,
        "files_copied_24h": 0,
        "files_created_24h": 0,
        "files_modified_24h": 0,
        "source_code_files_24h": 0,
        "zip_files_24h": 0,
        "office_files_24h": 0,
        "usb_inserts_24h": 0,
        "sensitive_files_24h": 0,
        "sensitive_matches": [],
        "top_matched_keywords": [],
        "sensitive_zip_count": 0,
        "sensitive_max_risk": 0,
        "network_upload_mb_24h": 0,
        "login_hour": 12,
        "weekend_activity": 0,
        "night_activity": 0,
        "top_folder_access": None,
        "folder_access_count": 0,
        "delete_freq_24h": 0,
        "rename_freq_24h": 0,
        "avg_cpu_usage": 0,
        "avg_ram_usage": 0,
        "avg_file_size_mb": 0,
        "process_starts_24h": 0,
        "process_stops_24h": 0,
        "event_count_24h": 0,
        "event_count_1h": 0
    }

def _category_file_count(events: list, extensions: set, keywords: list = None) -> int:
    """Count file operations matching specified extension set or keywords."""
    count = 0
    for e in events:
        if not e.get("event_type", "").startswith("file_"):
            continue
        fname = (e.get("filename") or "").lower()
        ext = (e.get("extension") or "").lower()
        details = (e.get("details") or "").lower()

        if ext in extensions or (keywords and any(k in fname or k in details for k in keywords)):
            # Expand summary counts like 'Copied 120 files'
            import re
            m = re.search(r"(\d+)\s*(?:files?|file operations)", details, re.IGNORECASE)
            if m:
                count += max(1, int(m.group(1)))
            else:
                count += 1
    return count

def _within_hours(ts, now, hours):
    if not ts:
        return False
    try:
        t = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
        return (now - t).total_seconds() <= hours * 3600
    except Exception:
        return False

def _sum_upload_mb(events):
    total = 0.0
    for e in events:
        if e.get("event_type") == "network_upload":
            v = _parse_mb(e.get("network_upload"))
            if v is not None:
                total += v
    return total

def _parse_mb(val):
    if val is None:
        return None
    s = str(val).strip().upper()
    m = re_match_mb(s)
    if m:
        return m
    return None

def re_match_mb(s):
    import re
    m = re.match(r"([0-9.]+)\s*(MB|GB|KB|B|TB)?", s)
    if not m:
        return None
    val, unit = float(m.group(1)), m.group(2) or "B"
    if unit == "GB":
        return val * 1024
    if unit == "KB":
        return val / 1024
    if unit == "TB":
        return val * 1024 * 1024
    if unit == "B":
        return val / (1024 * 1024)
    return val

def _file_op_count(events):
    """Count file operations, expanding summary events like 'Copied 120 files'."""
    total = 0
    for e in events:
        if e.get("event_type") in ("file_copy", "file_create", "file_modify", "file_move", "file_rename"):
            total += 1
            details = str(e.get("details") or "")
            import re
            m = re.search(r"(\d+)\s*(?:files?|file operations)", details, re.IGNORECASE)
            if m:
                total = max(total, int(m.group(1)))
    return total

def _get_login_hour(events):
    for e in events:
        if e.get("event_type") == "login" and e.get("timestamp"):
            t = _localize(e["timestamp"])
            if t is not None:
                return t.hour
    return None

def _has_weekend_activity(events):
    for e in events:
        t = _localize(e.get("timestamp"))
        if t is not None and t.weekday() >= 5:
            return True
    return False

def _has_night_activity(events):
    for e in events:
        t = _localize(e.get("timestamp"))
        if t is not None and (t.hour < 6 or t.hour >= 22):
            return True
    return False

def _folder_counts(events):
    counts = defaultdict(int)
    for e in events:
        f = e.get("folder")
        if f:
            counts[f] += 1
    return counts

def _top_folder(counts):
    if not counts:
        return None
    return max(counts, key=counts.get)

def _avg_metric(events, field):
    vals = []
    for e in events:
        v = e.get(field)
        if v is not None:
            try:
                vals.append(float(v))
            except Exception:
                pass
    return sum(vals)/len(vals) if vals else 0

def _avg_file_size_mb(events):
    vals = []
    for e in events:
        v = _parse_mb(e.get("size"))
        if v is not None:
            vals.append(v)
    return sum(vals)/len(vals) if vals else 0
