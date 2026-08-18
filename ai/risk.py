from typing import Dict, Optional, List
from ai.role_config import get_role_config

class RiskEngine:
    BASE_SCORE = 0
    EVENT_WEIGHTS = {
        "usb_insert": 20,
        "login": 5,
        "file_copy": 2,
        "file_create": 2,
        "file_delete": 3,
        "file_modify": 1,
        "file_rename": 4,
        "file_move": 4,
        "network_upload": 5,
        "process_start": 3,
        "process_stop": 1,
        "system_metrics": 0
    }

    # Default classification bands. Overridable per-call via `thresholds`
    # so persisted Settings (suspicious/high_risk thresholds) drive the engine.
    DEFAULT_THRESHOLDS = {
        "suspicious_threshold": 50,
        "high_risk_threshold": 75,
    }

    def calculate(
        self,
        features: Dict,
        anomalies: Dict,
        correlations: list,
        deviations: Dict,
        thresholds: Optional[Dict] = None,
        role_type: Optional[str] = None,
    ) -> dict:
        score = self.BASE_SCORE
        reasons = []
        role = role_type or features.get("role_type") or "General"
        role_cfg = features.get("role_config") or get_role_config(role)
        role_modifiers = role_cfg.get("risk_modifiers", {})

        last_triggered_rule = None

        # 1. USB Connection Check
        if features.get("usb_inserts_24h", 0) > 0:
            score += 10
            reasons.append("USB activity detected")

        # 2. Sensitive Company Asset Keywords Detection
        sensitive_matches = features.get("sensitive_matches", [])
        sensitive_zip_count = features.get("sensitive_zip_count", 0)

        if sensitive_matches:
            max_kw_count = max(len(m.get("matched_keywords", [])) for m in sensitive_matches)
            kw_names = []
            for m in sensitive_matches:
                for k in m.get("matched_keywords", []):
                    if k not in kw_names:
                        kw_names.append(k)
            
            top_file = sensitive_matches[0].get("filename", "file")
            
            # Base keyword risk: 1 -> +10, 2 -> +20, 3+ -> +30
            kw_score = 30 if max_kw_count >= 3 else (20 if max_kw_count == 2 else 10)
            score += kw_score

            if sensitive_zip_count > 0:
                score += 40
                kw_str = ", ".join(f"'{k}'" for k in kw_names[:3])
                reasons.append(
                    f"Sensitive asset movement detected: company-sensitive keyword(s) {kw_str} in compressed archive '{top_file}'. Risk increased by {40 + kw_score}."
                )
                last_triggered_rule = "Sensitive Compressed Archive Transfer"
            elif max_kw_count >= 3:
                kw_str = ", ".join(f"'{k}'" for k in kw_names[:4])
                reasons.append(
                    f"Multiple company-sensitive keywords ({kw_str}) detected in file operation(s). Risk increased by {kw_score}."
                )
                last_triggered_rule = "Multiple Sensitive Asset Keywords Detected"
            elif max_kw_count == 2:
                kw_str = ", ".join(f"'{k}'" for k in kw_names[:2])
                reasons.append(
                    f"Company-sensitive keywords ({kw_str}) detected in file '{top_file}'. Risk increased by {kw_score}."
                )
                last_triggered_rule = "Sensitive Asset Keyword Pair Match"
            elif max_kw_count == 1:
                reasons.append(
                    f"File name contains company-sensitive keyword '{kw_names[0]}'. Risk increased by {kw_score}."
                )
                last_triggered_rule = f"Sensitive Asset Keyword Match ({kw_names[0]})"

        # 3. Source Code / Archive / Role-Specific File Intelligence
        source_code_count = features.get("source_code_files_24h", 0)
        zip_count = features.get("zip_files_24h", 0)
        copies_24h = features.get("files_copied_24h", 0)

        # Source code & ZIP exfiltration / copying evaluation
        if source_code_count > 0 and zip_count > 0:
            if role == "Developer":
                boost = role_modifiers.get("source_code_copy_risk", 15)
                score += boost
                reasons.append(f"Source code and archive operations (+{boost}) match baseline Developer workflow.")
                if not last_triggered_rule:
                    last_triggered_rule = "Developer Source Code Workflow"
            elif role == "Finance":
                boost = role_modifiers.get("source_code_copy_risk", 50)
                score += boost
                reasons.append(f"Severe risk (+{boost}): Staging or copying source_code.zip is highly suspicious for Finance department.")
                last_triggered_rule = "Finance Source Code Exfiltration Warning"
            elif role == "HR":
                boost = role_modifiers.get("source_code_copy_risk", 40)
                score += boost
                reasons.append(f"High risk (+{boost}): Source code and archive file operations are abnormal for HR department.")
                last_triggered_rule = "HR Source Code Policy Violation"
            elif role == "Sales":
                boost = role_modifiers.get("source_code_copy_risk", 45)
                score += boost
                reasons.append(f"High risk (+{boost}): Source code and development archives are abnormal for Sales department.")
                last_triggered_rule = "Sales Code Access Violation"
            else:
                boost = role_modifiers.get("source_code_copy_risk", 30)
                score += boost
                reasons.append(f"Abnormal source code & archive transfer (+{boost}) detected for {role} role.")
                if not last_triggered_rule:
                    last_triggered_rule = f"{role} Archive Access Violation"
        elif zip_count > 0 and role == "Finance":
            boost = role_modifiers.get("zip_copy_risk", 50)
            score += boost
            reasons.append(f"Severe risk (+{boost}): Staging or copying ZIP archives is highly suspicious for Finance department.")
            last_triggered_rule = "Finance ZIP Archive Violation"
        elif source_code_count > 0 and not role_cfg.get("source_code_normal", False):
            boost = role_modifiers.get("source_code_copy_risk", 40)
            score += boost
            reasons.append(f"Risk increased (+{boost}) because employee role is {role} and source code operations are unusual for this department.")
            last_triggered_rule = f"{role} Source Code Baseline Triggered"

        # 4. Data staging: USB connection combined with file copies to media
        if features.get("usb_inserts_24h", 0) > 0 and copies_24h >= 5:
            score += 15
            reasons.append(f"USB device used with {copies_24h} file operations (possible data staging)")
            if not last_triggered_rule:
                last_triggered_rule = "USB Data Staging"

        # 5. Night & Outside working hours activity
        if features.get("night_activity"):
            score += 15
            reasons.append("Activity detected outside normal working hours")
            if not last_triggered_rule:
                last_triggered_rule = "Off-Hours Activity"

        # 6. Mass file operations / creation with Role Intelligence
        if copies_24h > 100 or features.get("files_created_24h", 0) > 100:
            boost = role_modifiers.get("mass_file_creation_risk", 30)
            score += boost
            if role == "Developer":
                reasons.append(f"Risk adjusted (+{boost}) for Developer role: mass file operations are standard during software compilation and development workflows.")
                if not last_triggered_rule:
                    last_triggered_rule = "Developer High File Creation Baseline"
            elif role == "HR":
                reasons.append(f"Risk increased (+{boost}) because employee role is HR and mass file creation is unusual for this department.")
                last_triggered_rule = "HR Mass File Operations Triggered"
            elif role == "Finance":
                reasons.append(f"Risk increased (+{boost}) because employee role is Finance and mass file operations are abnormal for this department.")
                last_triggered_rule = "Finance Mass File Triggered"
            elif role in ("Security Analyst", "IT Support", "Administrator"):
                reasons.append(f"Mass file operations (+{boost}) detected (within expected operating parameters for {role}).")
                if not last_triggered_rule:
                    last_triggered_rule = f"{role} Maintenance Baseline"
            else:
                reasons.append(f"Mass file operations (+{boost}) detected (>100 in 24h) for {role} role.")
                if not last_triggered_rule:
                    last_triggered_rule = "Mass File Operations"
        elif features.get("files_copied_per_hour", 0) > 50:
            if role in ("Developer", "Security Analyst", "IT Support", "Administrator"):
                score += 10
                reasons.append(f"High file operation rate (>50/hour) during active {role} session (+10)")
            else:
                score += 20
                reasons.append(f"High file operation rate (>50/hour) for {role} role (+20)")
            if not last_triggered_rule:
                last_triggered_rule = "Rapid File Rate"

        # 7. Evidence destruction / cover-up behavior
        delete_freq = features.get("delete_freq_24h", 0)
        if delete_freq >= 4:
            score += 15
            reasons.append(f"Mass file deletion detected ({delete_freq} files) - possible evidence destruction")
            last_triggered_rule = "Mass File Deletion Pattern"
        elif delete_freq >= 1:
            score += 8
            reasons.append("File deletion activity detected")

        # 8. Network Upload spikes
        upload = features.get("network_upload_mb_24h", 0)
        if upload > 500:
            score += 20
            reasons.append(f"Large network upload spike ({upload:.1f}MB)")
            if not last_triggered_rule:
                last_triggered_rule = "Large Network Upload Spike"
        elif upload > 100:
            score += 10
            reasons.append(f"Elevated upload volume ({upload:.1f}MB)")

        # 9. Weekend activity
        if features.get("weekend_activity"):
            score += 10
            reasons.append("Weekend activity detected")

        # 10. Hardware & Process metrics with Role Awareness
        if features.get("avg_cpu_usage", 0) > 90:
            score += 10
            reasons.append("Sustained high CPU usage")

        if features.get("avg_ram_usage", 0) > 90:
            score += 5
            reasons.append("Sustained high RAM usage")

        process_starts = features.get("process_starts_24h", 0)
        if process_starts > 15:
            if role == "Security Analyst":
                reasons.append("High process activity is normal for Security Analyst role (0 risk penalty)")
            elif role in ("IT Support", "Administrator"):
                score += 5
                reasons.append(f"Administrative process execution (+5) conforms to {role} duties")
            elif role in ("HR", "Finance"):
                score += 20
                reasons.append(f"Unusual process execution activity (+20) for {role} department")
                last_triggered_rule = f"{role} Process Execution Triggered"

        # 11. AI Anomaly detection
        if anomalies.get("is_anomaly"):
            score += 15
            reasons.append("Behavior deviates from baseline (AI anomaly)")
            if not last_triggered_rule:
                last_triggered_rule = "AI Behavior Anomaly"

        # 12. Correlations
        for corr in correlations:
            score += corr.get("score_boost", 0)
            reasons.append(corr.get("reason"))
            if not last_triggered_rule:
                last_triggered_rule = corr.get("name")

        score = max(0, min(100, score))
        status = self._classify(score, thresholds)
        return {
            "score": score,
            "status": status,
            "reasons": reasons,
            "role_type": role,
            "role_baseline": role_cfg,
            "last_triggered_rule": last_triggered_rule or "Standard Monitoring",
        }

    def _classify(self, score, thresholds: Optional[Dict] = None):
        cfg = {**self.DEFAULT_THRESHOLDS, **(thresholds or {})}
        suspicious = cfg.get("suspicious_threshold", 50)
        high = cfg.get("high_risk_threshold", 75)
        critical = min(100, high + 15)
        if score >= critical:
            return "Critical"
        if score >= high:
            return "High"
        if score >= suspicious:
            return "Medium"
        return "Safe"
