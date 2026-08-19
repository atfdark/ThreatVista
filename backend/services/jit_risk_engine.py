"""
ThreatVista Explainable Adaptive Dynamic Risk Scoring Engine.

Combines AI File Sensitivity Classification, Action Type analysis, and
Behavioral Anomaly Detection (UBA Digital Twin baseline deviations) into
an explainable 0 - 100 risk score and level (LOW, MEDIUM, HIGH).

Risk Factors:
1. File Sensitivity: PUBLIC (+0), INTERNAL (+10), CONFIDENTIAL (+25), RESTRICTED (+40)
2. Action Type: DELETE (+20), MOVE (+10), COPY (+15), USB COPY (+35)
3. Behavioral Anomalies & Digital Twin Deviations:
   - Low Anomaly (+10), Medium Anomaly (+20), High Anomaly (+35)
   - Mass File Access (+25)
   - Unusual Directory Access (+20)
   - Abnormal USB Activity (+20)
   - Off-Hours / Weekend Activity (+15)
   - Recent Action Attempt Bursts (+15)
   - History of Rejected Violations (+20)
"""
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from backend.models.database import ActionRequest, Employee
from backend.websocket.manager import manager


CLASSIFICATION_WEIGHTS = {
    "PUBLIC": 0,
    "INTERNAL": 10,
    "CONFIDENTIAL": 25,
    "RESTRICTED": 40,
}

ACTION_WEIGHTS = {
    "file_delete": 20,
    "delete": 20,
    "file_move": 10,
    "move": 10,
    "folder_move": 10,
    "file_copy": 15,
    "copy": 15,
    "usb_export": 35,
    "usb_copy": 35,
    "script_execution": 25,
}


def _is_after_hours(dt: Optional[datetime] = None) -> bool:
    """Check if current time is outside normal working hours (09:00 - 18:00) or on weekend."""
    now = dt or datetime.utcnow()
    # Add IST offset (+5.5h) for Indian Standard Time operating hours check
    local_time = now + timedelta(hours=5.5)
    
    # Weekend (Saturday = 5, Sunday = 6)
    if local_time.weekday() >= 5:
        return True
    
    # Hour of day (before 9 AM or after 6 PM)
    if local_time.hour < 9 or local_time.hour >= 18:
        return True
    
    return False


def _is_external_drive(file_path: str) -> bool:
    r"""Check if target path is located on an external/removable drive (e.g. E:\, D:\, /media)."""
    p = str(file_path or "").strip().upper()
    if p.startswith(("D:\\", "E:\\", "F:\\", "G:\\", "H:\\", "USB:", "/MEDIA", "/MNT")):
        return True
    return False


def calculate_risk_score(
    db: Optional[Session],
    employee_id: int,
    action_type: str,
    file_path: str,
    classification: str = "INTERNAL",
    target_time: Optional[datetime] = None,
) -> Dict:
    """Dynamically compute explainable risk score, level, and AI diagnostic trail.

    Returns:
        {
            "risk_score": 87,
            "risk_level": "HIGH",
            "explanation": [
                "Restricted file (+40)",
                "Delete attempt (+20)",
                "External drive detected (+20)",
                "After-hours activity (+15)",
                "Mass file access (250 files vs 10 avg)"
            ],
            "anomaly_score": 85,
            "anomaly_severity": "HIGH",
            "anomaly_indicators": [...]
        }
    """
    score = 0
    explanation: List[str] = []
    anomaly_score = 0
    anomaly_severity = "LOW"
    anomaly_indicators = []

    # 1. File Classification Score
    cls_upper = (classification or "INTERNAL").upper()
    cls_weight = CLASSIFICATION_WEIGHTS.get(cls_upper, 10)
    score += cls_weight
    if cls_upper == "RESTRICTED":
        explanation.append("Restricted file")
    elif cls_upper == "CONFIDENTIAL":
        explanation.append("Confidential file")
    elif cls_upper == "INTERNAL":
        explanation.append("Internal corporate document")

    # 2. Action Type Score
    act_norm = (action_type or "file_delete").lower()
    act_weight = ACTION_WEIGHTS.get(act_norm, 20)
    score += act_weight
    if "delete" in act_norm:
        explanation.append("Delete attempt")
    elif "usb" in act_norm:
        explanation.append("USB copy attempt")
    elif "copy" in act_norm:
        explanation.append("File copy operation")
    elif "move" in act_norm:
        explanation.append("File move operation")

    # 3. Behavioral Factors (Environmental)
    if _is_external_drive(file_path) or "usb" in act_norm:
        score += 20
        explanation.append("External drive detected")

    if _is_after_hours(target_time):
        score += 15
        explanation.append("After-hours activity")

    # 4. Behavioral Anomaly Detection & Digital Twin Integration
    if db is not None and employee_id:
        try:
            from backend.services.anomaly_detection_service import detect_behavior_anomaly
            anom = detect_behavior_anomaly(
                db=db,
                employee_id=employee_id,
                file_path=file_path,
                action_type=action_type,
                classification=cls_upper,
                target_time=target_time,
                is_usb=_is_external_drive(file_path) or "usb" in act_norm,
            )
            anomaly_score = anom.get("anomaly_score", 0)
            anomaly_severity = anom.get("severity", "LOW")
            anomaly_indicators = anom.get("indicators", [])
            devs = anom.get("deviations", {})

            # Add anomaly tier weight
            if anomaly_severity == "HIGH":
                score += 35
                explanation.append("Behavior anomaly detected (HIGH severity)")
            elif anomaly_severity == "MEDIUM":
                score += 20
                explanation.append("Behavior anomaly detected (MEDIUM severity)")
            elif anomaly_severity == "LOW" and anomaly_score > 0:
                score += 10

            # Add specific anomaly indicator tags
            if devs.get("volume_multiplier", 1.0) >= 3.0:
                score += 25
            if devs.get("directory_outlier"):
                score += 20
            if devs.get("usb_outlier"):
                score += 20

            for ind in anomaly_indicators:
                if ind not in explanation and not any(ind.lower() in e.lower() for e in explanation):
                    explanation.append(ind)

        except Exception as e:
            print(f"[-] Anomaly detection eval error: {e}")

    # 5. Database Historical Context (Recent attempt bursts & rejections)
    if db is not None and employee_id:
        try:
            now = target_time or datetime.utcnow()
            one_hour_ago = now - timedelta(hours=1)
            
            # Check recent attempts in last hour
            recent_attempts = (
                db.query(ActionRequest)
                .filter(
                    ActionRequest.employee_id == employee_id,
                    ActionRequest.requested_at >= one_hour_ago,
                )
                .count()
            )
            if recent_attempts >= 2:
                score += 15
                if "Multiple attempts within 1 hour" not in explanation:
                    explanation.append("Multiple attempts within 1 hour")

            # Check history of rejected requests
            rejected_history = (
                db.query(ActionRequest)
                .filter(
                    ActionRequest.employee_id == employee_id,
                    ActionRequest.status == "REJECTED",
                )
                .count()
            )
            if rejected_history >= 1:
                score += 20
                if "Previous rejected requests in history" not in explanation:
                    explanation.append("Previous rejected requests in history")
        except Exception:
            pass

    # Cap score between 0 and 100
    risk_score = max(0, min(100, score))

    # Determine Risk Level: 0-25 = LOW, 26-60 = MEDIUM, 61-100 = HIGH
    if risk_score >= 61:
        risk_level = "HIGH"
    elif risk_score >= 26:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Broadcast risk escalation event if score is elevated
    if risk_score >= 65 and db is not None and employee_id:
        try:
            emp = db.query(Employee).filter(Employee.id == employee_id).first()
            if emp:
                manager.broadcast_nowait({
                    "type": "RISK_ESCALATED",
                    "employee_id": employee_id,
                    "employee_name": emp.name,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "explanation": explanation,
                })
        except Exception:
            pass

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "explanation": explanation,
        "anomaly_score": anomaly_score,
        "anomaly_severity": anomaly_severity,
        "anomaly_indicators": anomaly_indicators,
    }
