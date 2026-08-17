from typing import List, Dict
from datetime import datetime, timedelta
from collections import defaultdict

class CorrelationEngine:
    # A batch of file operations is treated as a burst incident once it exceeds
    # this many events of the same type within one ~1s agent batch.
    BURST_THRESHOLD = 50

    # Human-facing identity for each burstable file-op event type.
    BURST_TYPES = {
        "file_create": {"title": "Mass File Activity", "icon": "📁"},
        "file_delete": {"title": "Mass File Deletion", "icon": "🗑️"},
        "file_copy": {"title": "Mass File Copy", "icon": "📋"},
        "file_modify": {"title": "Mass File Modification", "icon": "✏️"},
        "file_rename": {"title": "Mass File Rename", "icon": "📝"},
        "file_move": {"title": "Mass File Move", "icon": "📂"},
    }

    def __init__(self):
        self.rules = [
            self._rule_usb_mass_copy,
            self._rule_usb_data_staging,
            self._rule_night_upload,
            self._rule_evidence_destruction,
            self._rule_process_file_correlation,
            self._rule_rapid_file_ops
        ]

    def correlate(self, recent_events: List[dict], features: dict) -> List[dict]:
        incidents = []
        for rule in self.rules:
            res = rule(recent_events, features)
            if res:
                incidents.append(res)
        return incidents

    def analyze_batch(self, events: List[dict]) -> List[dict]:
        """Detect burst incidents inside one agent batch.

        Groups the batch's file operations by type and, for any type hitting
        ``BURST_THRESHOLD`` events, emits a single consolidated incident summary
        (count, folder, duration, severity) instead of one UI update per event.
        """
        buckets = defaultdict(list)
        for evt in events:
            if evt.get("event_type") in self.BURST_TYPES:
                buckets[evt.get("event_type")].append(evt)

        incidents = []
        for event_type, evts in buckets.items():
            count = len(evts)
            if count < self.BURST_THRESHOLD:
                continue
            meta = self.BURST_TYPES[event_type]
            folder = self._most_common_folder(evts)
            duration = self._span_seconds(evts)
            severity, boost = self._severity_for(count)
            incidents.append({
                "name": meta["title"],
                "icon": meta["icon"],
                "event_type": event_type,
                "severity": severity,
                "count": count,
                "folder": folder,
                "duration_seconds": round(duration, 1),
                "score_boost": boost,
                "reason": f"{meta['title']} detected: {count} file operations in {duration:.1f}s.",
            })

        incidents.sort(key=lambda i: i["count"], reverse=True)
        return incidents

    @staticmethod
    def _most_common_folder(events):
        counts = defaultdict(int)
        for e in events:
            f = e.get("folder")
            if f:
                counts[f] += 1
        return max(counts, key=counts.get) if counts else None

    @staticmethod
    def _span_seconds(events):
        """Duration between the first and last timestamp in seconds."""
        times = []
        for e in events:
            ts = e.get("timestamp")
            try:
                t = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
                times.append(t)
            except Exception:
                continue
        if len(times) < 2:
            return 0.0
        span = (max(times) - min(times)).total_seconds()
        return max(span, 0.1)  # never claim zero duration for an instant burst

    @staticmethod
    def _severity_for(count):
        if count >= 150:
            return "High", 25
        if count >= 100:
            return "High", 20
        return "Medium", 15

    def _rule_usb_mass_copy(self, events, features):
        # Use 24h features so USB inserts outside the recent-event slice still count.
        copies = features.get("files_copied_24h", 0)
        if features.get("usb_inserts_24h", 0) > 0 and copies > 50:
            return {
                "name": "USB Mass Exfiltration",
                "severity": "High",
                "reason": f"USB device inserted followed by {copies} file operations in 24h. Possible mass data exfiltration.",
                "score_boost": 25
            }
        return None

    def _rule_usb_data_staging(self, events, features):
        copies = features.get("files_copied_24h", 0)
        if features.get("usb_inserts_24h", 0) > 0 and copies >= 5:
            return {
                "name": "USB Data Staging",
                "severity": "Medium",
                "reason": f"USB device connected followed by {copies} file operations. Possible data staging to removable media.",
                "score_boost": 10
            }
        return None

    def _rule_evidence_destruction(self, events, features):
        deletes = [e for e in events if e.get("event_type") == "file_delete"]
        usb_removes = [e for e in events if e.get("event_type") == "usb_remove"]
        procs = [e for e in events if e.get("event_type") == "process_start"]
        if len(deletes) >= 3 and (usb_removes or procs):
            return {
                "name": "Evidence Destruction Pattern",
                "severity": "High",
                "reason": f"Deletion of {len(deletes)} files following USB removal / cleanup process. Possible evidence destruction.",
                "score_boost": 30
            }
        return None

    def _rule_night_upload(self, events, features):
        upload = features.get("network_upload_mb_24h", 0)
        night = features.get("night_activity", 0)
        if upload > 100 and night:
            return {
                "name": "Night Upload Spike",
                "severity": "High",
                "reason": f"Unusual outbound upload of {upload:.1f}MB detected during night hours.",
                "score_boost": 20
            }
        return None

    def _rule_process_file_correlation(self, events, features):
        procs = [e for e in events if e.get("event_type") == "process_start"]
        copies = features.get("files_copied_24h", 0)
        if procs and copies > 30:
            return {
                "name": "Suspicious Process + File Activity",
                "severity": "Medium",
                "reason": f"New process(es) started alongside {copies} file operations. Possible automated exfiltration.",
                "score_boost": 15
            }
        return None

    def _rule_rapid_file_ops(self, events, features):
        per_hour = features.get("files_copied_per_hour", 0)
        if per_hour > 50:
            return {
                "name": "Rapid File Operations",
                "severity": "Medium",
                "reason": f"Extremely high file operation rate: {per_hour} ops/hour.",
                "score_boost": 15
            }
        return None
