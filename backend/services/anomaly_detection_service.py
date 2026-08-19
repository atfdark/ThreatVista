"""
ThreatVista Behavioral Anomaly Detection Engine.

Compares live telemetry and JIT action authorization requests against the
employee's Digital Twin behavioral baseline across 5 key dimensions:
1. Time Anomalies (off-hours, early morning, or weekend operations)
2. Volume Anomalies (sudden spikes / mass file access above daily baseline)
3. USB Anomalies (removable drive usage when baseline is Rare/None)
4. Sensitivity Anomalies (accessing RESTRICTED/CONFIDENTIAL data above normal baseline)
5. Directory Anomalies (navigating into foreign departmental directories)
"""
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from backend.models.database import Employee, Event, BehavioralAnomalyLog, UserBehaviorProfile
from backend.websocket.manager import manager
from backend.services.user_behavior_service import get_or_create_behavior_profile


def detect_behavior_anomaly(
    db: Session,
    employee_id: int,
    file_path: Optional[str] = None,
    action_type: Optional[str] = None,
    classification: Optional[str] = None,
    target_time: Optional[datetime] = None,
    recent_file_count: Optional[int] = None,
    is_usb: bool = False,
) -> Dict:
    """Evaluate behavioral deviation against employee Digital Twin baseline.

    Returns:
        {
            "anomaly_score": 87,
            "severity": "HIGH",
            "indicators": [
                "After-hours activity (02:15 AM)",
                "Mass file access (250 files vs 10 avg)",
                "Unusual USB activity",
                "Restricted data access"
            ],
            "deviations": {
                "time_deviation_hours": 7.0,
                "volume_multiplier": 25.0,
                "directory_outlier": True,
                "sensitivity_escalation": True,
                "usb_outlier": True
            }
        }
    """
    emp = db.query(Employee).filter(Employee.id == employee_id).first()
    if not emp:
        return {
            "anomaly_score": 0,
            "severity": "LOW",
            "indicators": [],
            "deviations": {},
        }

    profile = get_or_create_behavior_profile(db, employee_id)
    now = target_time or datetime.utcnow()
    # IST local time representation
    local_time = now + timedelta(hours=5.5)
    current_hour = local_time.hour + (local_time.minute / 60.0)

    score = 0
    indicators: List[str] = []
    deviations: Dict[str, any] = {}

    # -------------------------------------------------------------------------
    # 1. TIME ANOMALIES
    # -------------------------------------------------------------------------
    login_h = profile.avg_login_hour or 9.0
    logout_h = profile.avg_logout_hour or 18.0
    
    is_weekend = local_time.weekday() >= 5
    time_dev_hours = 0.0

    if current_hour < login_h:
        time_dev_hours = round(login_h - current_hour, 1)
    elif current_hour > logout_h:
        time_dev_hours = round(current_hour - logout_h, 1)

    if is_weekend:
        score += 25
        time_str = local_time.strftime("%I:%M %p")
        indicators.append(f"Weekend activity ({time_str} on {local_time.strftime('%A')})")
        deviations["time_deviation_hours"] = round(time_dev_hours + 12.0, 1)
    elif time_dev_hours >= 3.0:
        score += 25
        time_str = local_time.strftime("%I:%M %p")
        indicators.append(f"After-hours activity ({time_str} - {int(time_dev_hours)}h off baseline)")
        deviations["time_deviation_hours"] = time_dev_hours
    elif time_dev_hours >= 1.0:
        score += 15
        time_str = local_time.strftime("%I:%M %p")
        indicators.append(f"Off-hours activity ({time_str})")
        deviations["time_deviation_hours"] = time_dev_hours

    # -------------------------------------------------------------------------
    # 2. VOLUME ANOMALIES (Mass File Activity)
    # -------------------------------------------------------------------------
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_files_db = (
        db.query(Event)
        .filter(
            Event.employee_id == employee_id,
            Event.timestamp >= today_start,
            Event.event_type.like("file_%"),
        )
        .count()
    )
    today_files = recent_file_count if recent_file_count is not None else today_files_db
    avg_daily = max(5.0, profile.avg_files_accessed_per_day or 15.0)
    vol_multiplier = round(today_files / avg_daily, 1)

    if today_files >= 100 or vol_multiplier >= 5.0:
        score += 30
        indicators.append(f"Mass file access ({today_files} files vs {int(avg_daily)} avg)")
        deviations["volume_multiplier"] = vol_multiplier
        deviations["today_files"] = today_files
    elif today_files >= 40 or vol_multiplier >= 2.5:
        score += 15
        indicators.append(f"Elevated file activity ({today_files} files today)")
        deviations["volume_multiplier"] = vol_multiplier
        deviations["today_files"] = today_files

    # -------------------------------------------------------------------------
    # 3. USB ANOMALIES
    # -------------------------------------------------------------------------
    p_str = str(file_path or "").upper()
    has_usb = is_usb or "usb" in str(action_type or "").lower() or p_str.startswith(("D:\\", "E:\\", "F:\\", "USB:", "/MEDIA"))
    
    if has_usb:
        if (profile.avg_usb_usage_per_week or 0.0) <= 0.5:
            score += 25
            indicators.append("Unusual USB activity (Baseline: Rare/None)")
            deviations["usb_outlier"] = True
        else:
            score += 15
            indicators.append("Removable drive attachment detected")
            deviations["usb_outlier"] = False

    # -------------------------------------------------------------------------
    # 4. SENSITIVITY ANOMALIES (Sensitivity Escalation)
    # -------------------------------------------------------------------------
    cls_upper = (classification or "INTERNAL").upper()
    typical_cls = (profile.typical_sensitivity or "INTERNAL").upper()
    
    if cls_upper == "RESTRICTED":
        if typical_cls != "RESTRICTED":
            score += 25
            indicators.append(f"Restricted data access (Above normal {typical_cls} baseline)")
            deviations["sensitivity_escalation"] = True
    elif cls_upper == "CONFIDENTIAL":
        if typical_cls in ("INTERNAL", "PUBLIC"):
            score += 15
            indicators.append(f"Confidential data access (Above normal {typical_cls} baseline)")
            deviations["sensitivity_escalation"] = True

    # -------------------------------------------------------------------------
    # 5. DIRECTORY ANOMALIES (Foreign Namespace Access)
    # -------------------------------------------------------------------------
    if file_path:
        path_lower = file_path.lower().replace("\\", "/")
        common_dirs = []
        try:
            common_dirs = [d.lower() for d in json.loads(profile.common_directories_json or "[]")]
        except Exception:
            common_dirs = ["projects", "documents"]

        sensitive_dirs = ["finance", "payroll", "accounting", "hr", "executive", "legal", "passwords", "vault"]
        # Check if accessing a sensitive foreign department folder not in common dirs
        for s_dir in sensitive_dirs:
            if s_dir in path_lower and not any(s_dir in cd for cd in common_dirs):
                score += 20
                indicators.append(f"Unusual directory access ({s_dir.capitalize()}/)")
                deviations["directory_outlier"] = True
                break

    # Cap anomaly score at 100
    anomaly_score = max(0, min(100, score))

    if anomaly_score >= 65:
        severity = "HIGH"
    elif anomaly_score >= 35:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # Persist anomaly log in DB if meaningful
    if anomaly_score >= 35:
        try:
            log = BehavioralAnomalyLog(
                employee_id=employee_id,
                anomaly_score=anomaly_score,
                severity=severity,
                indicators_json=json.dumps(indicators),
                deviations_json=json.dumps(deviations),
                context=f"Action: {action_type or 'telemetry'} on '{file_path or 'endpoint'}'",
                detected_at=now,
            )
            db.add(log)
            db.commit()
        except Exception:
            pass

    # WebSocket broadcast for high anomalies
    if anomaly_score >= 50:
        manager.broadcast_nowait({
            "type": "ANOMALY_DETECTED",
            "employee_id": employee_id,
            "employee_name": emp.name,
            "anomaly_score": anomaly_score,
            "severity": severity,
            "indicators": indicators,
            "timestamp": now.isoformat(),
        })

    return {
        "anomaly_score": anomaly_score,
        "severity": severity,
        "indicators": indicators,
        "deviations": deviations,
    }
