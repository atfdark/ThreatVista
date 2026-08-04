from typing import List, Dict
from datetime import datetime, timedelta

class CorrelationEngine:
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

    def _rule_usb_mass_copy(self, events, features):
        usb = [e for e in events if e.get("event_type") == "usb_insert"]
        copies = features.get("files_copied_24h", 0)
        if usb and copies > 50:
            return {
                "name": "USB Mass Exfiltration",
                "severity": "High",
                "reason": f"USB device inserted followed by {copies} file operations in 24h. Possible mass data exfiltration.",
                "score_boost": 25
            }
        return None

    def _rule_usb_data_staging(self, events, features):
        usb = [e for e in events if e.get("event_type") == "usb_insert"]
        copies = features.get("files_copied_24h", 0)
        if usb and copies >= 5:
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
