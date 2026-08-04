from typing import Dict, Optional

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
    ) -> dict:
        score = self.BASE_SCORE
        reasons = []

        if features.get("usb_inserts_24h", 0) > 0:
            score += 20
            reasons.append("USB device inserted")

        # Data staging: USB connection combined with any file copies to media
        copies_24h = features.get("files_copied_24h", 0)
        if features.get("usb_inserts_24h", 0) > 0 and copies_24h >= 5:
            score += 10
            reasons.append(f"USB device used with {copies_24h} file operations (possible data staging)")

        if features.get("night_activity"):
            score += 20
            reasons.append("Activity detected outside normal hours")

        if copies_24h > 100:
            score += 25
            reasons.append("Mass file operations detected (>100 in 24h)")
        elif features.get("files_copied_per_hour", 0) > 50:
            score += 20
            reasons.append("High file operation rate (>50/hour)")

        # Evidence destruction / cover-up behavior
        delete_freq = features.get("delete_freq_24h", 0)
        if delete_freq >= 4:
            score += 15
            reasons.append(f"Mass file deletion detected ({delete_freq} files) - possible evidence destruction")
        elif delete_freq >= 1:
            score += 8
            reasons.append("File deletion activity detected")

        upload = features.get("network_upload_mb_24h", 0)
        if upload > 500:
            score += 20
            reasons.append(f"Large network upload spike ({upload:.1f}MB)")
        elif upload > 100:
            score += 10
            reasons.append(f"Elevated upload volume ({upload:.1f}MB)")

        if features.get("weekend_activity"):
            score += 10
            reasons.append("Weekend activity detected")

        if features.get("avg_cpu_usage", 0) > 90:
            score += 10
            reasons.append("Sustained high CPU usage")

        if features.get("avg_ram_usage", 0) > 90:
            score += 5
            reasons.append("Sustained high RAM usage")

        if anomalies.get("is_anomaly"):
            score += 15
            reasons.append("Behavior deviates from baseline (AI anomaly)")

        for corr in correlations:
            score += corr.get("score_boost", 0)
            reasons.append(corr.get("reason"))

        score = max(0, min(100, score))
        status = self._classify(score, thresholds)
        return {"score": score, "status": status, "reasons": reasons}

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
