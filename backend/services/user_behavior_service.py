"""
ThreatVista User Behavior Analytics (UBA) Service.

Learns, tracks, and continuously updates baseline activity profiles for each employee:
- Rolling 7-day and 30-day behavioral metrics
- Login/Logout and operational hours
- File creation, modification, copy, and deletion velocity
- USB and removable drive interaction habits
- Departmental directory clusters and file sensitivity tendencies
"""
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.models.database import Employee, Event, UserBehaviorProfile


# Default role-based baseline templates for cold-start initialization
ROLE_BASELINES = {
    "Developer": {
        "avg_login_hour": 9.5,
        "avg_logout_hour": 18.5,
        "avg_files_accessed": 45.0,
        "avg_files_deleted": 3.0,
        "avg_files_copied": 8.0,
        "avg_sensitive_access": 2.0,
        "avg_usb_usage": 0.0,
        "common_directories": ["src", "projects", "code", "repos", "build"],
        "typical_sensitivity": "INTERNAL",
    },
    "HR": {
        "avg_login_hour": 9.0,
        "avg_logout_hour": 17.5,
        "avg_files_accessed": 20.0,
        "avg_files_deleted": 1.0,
        "avg_files_copied": 4.0,
        "avg_sensitive_access": 6.0,
        "avg_usb_usage": 0.0,
        "common_directories": ["hr", "employees", "resumes", "payroll", "documents"],
        "typical_sensitivity": "CONFIDENTIAL",
    },
    "Finance": {
        "avg_login_hour": 9.0,
        "avg_logout_hour": 18.0,
        "avg_files_accessed": 25.0,
        "avg_files_deleted": 1.0,
        "avg_files_copied": 5.0,
        "avg_sensitive_access": 8.0,
        "avg_usb_usage": 0.0,
        "common_directories": ["finance", "ledgers", "invoices", "accounting", "tax"],
        "typical_sensitivity": "CONFIDENTIAL",
    },
    "General": {
        "avg_login_hour": 9.0,
        "avg_logout_hour": 17.5,
        "avg_files_accessed": 15.0,
        "avg_files_deleted": 1.0,
        "avg_files_copied": 3.0,
        "avg_sensitive_access": 1.0,
        "avg_usb_usage": 0.0,
        "common_directories": ["documents", "projects", "downloads", "desktop"],
        "typical_sensitivity": "INTERNAL",
    },
}


def profile_to_dict(profile: UserBehaviorProfile) -> Dict:
    """Format UserBehaviorProfile into JSON-serializable dictionary."""
    common_dirs = []
    if profile.common_directories_json:
        try:
            common_dirs = json.loads(profile.common_directories_json)
        except Exception:
            common_dirs = ["Projects", "Documents"]

    emp = profile.employee
    return {
        "id": profile.id,
        "employee_id": profile.employee_id,
        "employee_name": emp.name if emp else "Unknown",
        "employee_role": emp.role_type if emp else "General",
        "employee_department": emp.department if emp else "General",
        "avg_login_hour": round(profile.avg_login_hour, 1),
        "avg_logout_hour": round(profile.avg_logout_hour, 1),
        "normal_working_hours": f"{int(profile.avg_login_hour):02d}:00 - {int(profile.avg_logout_hour):02d}:00",
        "avg_files_accessed_per_day": round(profile.avg_files_accessed_per_day, 1),
        "avg_files_deleted_per_day": round(profile.avg_files_deleted_per_day, 1),
        "avg_files_copied_per_day": round(profile.avg_files_copied_per_day, 1),
        "avg_sensitive_file_accesses": round(profile.avg_sensitive_file_accesses, 1),
        "avg_usb_usage_per_week": round(profile.avg_usb_usage_per_week, 1),
        "common_directories": common_dirs,
        "typical_sensitivity": profile.typical_sensitivity,
        "last_updated": profile.last_updated.isoformat() if profile.last_updated else None,
    }


def get_or_create_behavior_profile(db: Session, employee_id: int) -> UserBehaviorProfile:
    """Retrieve existing behavior profile or initialize from role baseline."""
    profile = db.query(UserBehaviorProfile).filter(UserBehaviorProfile.employee_id == employee_id).first()
    if profile:
        return profile

    emp = db.query(Employee).filter(Employee.id == employee_id).first()
    if not emp:
        return None
    role = emp.role_type if emp and emp.role_type else "General"
    template = ROLE_BASELINES.get(role, ROLE_BASELINES["General"])

    profile = UserBehaviorProfile(
        employee_id=employee_id,
        avg_login_hour=template["avg_login_hour"],
        avg_logout_hour=template["avg_logout_hour"],
        avg_files_accessed_per_day=template["avg_files_accessed"],
        avg_files_deleted_per_day=template["avg_files_deleted"],
        avg_files_copied_per_day=template["avg_files_copied"],
        avg_sensitive_file_accesses=template["avg_sensitive_access"],
        avg_usb_usage_per_week=template["avg_usb_usage"],
        common_directories_json=json.dumps(template["common_directories"]),
        typical_sensitivity=template["typical_sensitivity"],
        last_updated=datetime.utcnow(),
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


def update_employee_behavior_profile(db: Session, employee_id: int) -> UserBehaviorProfile:
    """Recompute rolling 30-day telemetry averages and directory clusters."""
    profile = get_or_create_behavior_profile(db, employee_id)
    emp = db.query(Employee).filter(Employee.id == employee_id).first()
    if not emp:
        return profile

    now = datetime.utcnow()
    thirty_days_ago = now - timedelta(days=30)

    # Fetch historical events
    events = (
        db.query(Event)
        .filter(
            Event.employee_id == employee_id,
            Event.timestamp >= thirty_days_ago,
        )
        .all()
    )

    if not events or len(events) < 5:
        # Not enough historical events — keep initialized role baseline
        return profile

    # Group events by active days
    days_set = set(e.timestamp.date() for e in events if e.timestamp)
    total_days = max(1, len(days_set))

    file_events = [e for e in events if (e.event_type or "").startswith("file_")]
    delete_events = [e for e in events if e.event_type in ("file_delete", "folder_delete")]
    copy_events = [e for e in events if e.event_type in ("file_copy", "folder_copy")]
    usb_events = [e for e in events if e.event_type == "usb_insert"]

    # Compute operational hours (IST offset +5.5h)
    event_hours = [((e.timestamp + timedelta(hours=5.5)).hour + (e.timestamp.minute / 60.0)) for e in events if e.timestamp]
    if event_hours:
        avg_hour = sum(event_hours) / len(event_hours)
        min_hour = max(6.0, min(event_hours))
        max_hour = min(23.0, max(event_hours))
        profile.avg_login_hour = round(min_hour, 1)
        profile.avg_logout_hour = round(max(max_hour, min_hour + 8.0), 1)

    profile.avg_files_accessed_per_day = round(len(file_events) / total_days, 1)
    profile.avg_files_deleted_per_day = round(len(delete_events) / total_days, 1)
    profile.avg_files_copied_per_day = round(len(copy_events) / total_days, 1)
    
    # USB usage scaled per week
    weeks = max(1.0, total_days / 7.0)
    profile.avg_usb_usage_per_week = round(len(usb_events) / weeks, 1)

    # Extract distinct directory clusters
    dir_counts: Dict[str, int] = {}
    for e in file_events:
        folder = e.folder or (e.details if "in " in (e.details or "") else None)
        if folder:
            # Extract top folder segment
            seg = folder.replace("\\", "/").strip("/").split("/")
            top_folder = seg[-1] if seg else folder
            dir_counts[top_folder] = dir_counts.get(top_folder, 0) + 1

    if dir_counts:
        top_dirs = [k for k, _ in sorted(dir_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
        profile.common_directories_json = json.dumps(top_dirs)

    profile.last_updated = now
    db.commit()
    db.refresh(profile)
    return profile
