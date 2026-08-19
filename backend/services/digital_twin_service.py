"""
ThreatVista Employee Digital Twin Service.

Generates a behavioral fingerprint snapshot for an employee, capturing:
- Normal operating hours and working schedule
- Baseline file access and deletion velocity
- USB and external storage attachment habits
- Common directory namespaces and typical file sensitivity tiers
- Baseline threat/risk profile
"""
from typing import Dict
from sqlalchemy.orm import Session

from backend.models.database import Employee
from backend.services.user_behavior_service import get_or_create_behavior_profile, profile_to_dict


def generate_employee_baseline(db: Session, employee_id: int) -> Dict:
    """Generate human-readable Digital Twin behavioral fingerprint.

    Example:
    {
        "employee_id": 1,
        "employee": "John Doe",
        "role": "Developer",
        "department": "Engineering",
        "normal_hours": "09:00 - 18:00",
        "avg_files_per_day": 14.0,
        "avg_sensitive_access": 2.0,
        "usb_frequency": "Rare",
        "risk_profile": "Low",
        "common_directories": ["src", "projects", "repos"],
        "typical_sensitivity": "INTERNAL"
    }
    """
    emp = db.query(Employee).filter(Employee.id == employee_id).first()
    if not emp:
        raise ValueError(f"Employee #{employee_id} not found")

    profile = get_or_create_behavior_profile(db, employee_id)
    p_dict = profile_to_dict(profile)

    # Classify USB frequency
    usb_rate = profile.avg_usb_usage_per_week
    if usb_rate <= 0.1:
        usb_freq = "None"
    elif usb_rate <= 1.0:
        usb_freq = "Rare"
    elif usb_rate <= 3.0:
        usb_freq = "Moderate"
    else:
        usb_freq = "Frequent"

    # Risk profile baseline classification
    r_score = emp.risk_score or 0
    if r_score >= 75:
        r_profile = "High"
    elif r_score >= 40:
        r_profile = "Medium"
    else:
        r_profile = "Low"

    return {
        "employee_id": emp.id,
        "employee": emp.name,
        "role": emp.role_type or "General",
        "department": emp.department or "General",
        "normal_hours": p_dict["normal_working_hours"],
        "avg_files_per_day": p_dict["avg_files_accessed_per_day"],
        "avg_files_deleted_per_day": p_dict["avg_files_deleted_per_day"],
        "avg_sensitive_access": p_dict["avg_sensitive_file_accesses"],
        "usb_frequency": usb_freq,
        "usb_events_per_week": p_dict["avg_usb_usage_per_week"],
        "risk_profile": r_profile,
        "common_directories": p_dict["common_directories"],
        "typical_sensitivity": p_dict["typical_sensitivity"],
        "last_synced": p_dict["last_updated"],
    }
