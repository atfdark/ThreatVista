"""
ThreatVista agent (device) service.

Manages the per-employee endpoint Device profile: token-based enrollment,
registration at agent startup, and periodic heartbeats that drive online/offline
status and endpoint health.
"""
import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.models.database import AgentEnrollmentToken, Device, Employee

# An employee is considered online while a heartbeat was received within this
# window. The endpoint agent heartbeats every endpoint_poll_seconds (default
# 30s), so 180s gives a stable lease while still surfacing real offline states.
HEARTBEAT_TIMEOUT_SECONDS = 180

# Enrollment tokens expire shortly after issue and are single-use, so a leaked
# token cannot register a device later on.
ENROLLMENT_TOKEN_TTL_MINUTES = 10


def _now():
    return datetime.utcnow()


def resolve_employee_by_email(db: Session, email: str) -> Optional[Employee]:
    """Look up an Employee row by email (case-insensitive)."""
    if not email:
        return None
    return (
        db.query(Employee)
        .filter(func.lower(Employee.email) == email.strip().lower())
        .first()
    )


def create_enrollment_token(db: Session, employee: Employee, backend_url: str) -> Dict:
    """Issue a fresh one-time enrollment token for an employee's device.

    Returns the payload the employee page needs to build the downloadable
    ``threatvista-agent-config.json`` (token + backend URL only — no email).
    """
    token = uuid.uuid4().hex
    now = _now()
    expires_at = now + timedelta(minutes=ENROLLMENT_TOKEN_TTL_MINUTES)
    row = AgentEnrollmentToken(
        employee_id=employee.id,
        token=token,
        created_at=now,
        expires_at=expires_at,
        used=False,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {
        "token": token,
        "employee_id": employee.id,
        "employee_name": employee.name,
        "employee_email": employee.email,
        "backend_url": backend_url,
        "expires_at": expires_at.isoformat(),
        "expires_in_seconds": int((expires_at - now).total_seconds()),
    }


def validate_enrollment_token(db: Session, token: str) -> Employee:
    """Validate a token without consuming it. Raises ValueError on any failure.

    Mirrors the HTTP status mapping in the route: unknown/expired/used tokens are
    all rejected (401) so an attacker cannot distinguish the failure reason.
    """
    row = db.query(AgentEnrollmentToken).filter(AgentEnrollmentToken.token == token).first()
    if row is None:
        raise ValueError("Invalid enrollment token")
    if row.used:
        raise ValueError("Enrollment token has already been used")
    if _now() > row.expires_at:
        raise ValueError("Enrollment token has expired")
    employee = db.query(Employee).filter(Employee.id == row.employee_id).first()
    if employee is None:
        raise ValueError("Invalid enrollment token")
    return employee


def consume_enrollment_token(db: Session, token: str, device_id: str) -> None:
    """Mark a validated token as used, recording the device it registered."""
    row = db.query(AgentEnrollmentToken).filter(AgentEnrollmentToken.token == token).first()
    if row is None:
        return
    row.used = True
    row.device_id = device_id
    db.commit()


def register_device(db: Session, employee_id: int, info: Dict) -> Dict:
    """Create/update the Device profile for an employee (one device each).

    Returns ``{employee_id, device_id, employee_name, employee_email}`` so the
    agent can attach identity to every subsequent event and heartbeat. Upserting
    on ``Device.employee_id`` makes re-enrollment safe: a device that is already
    registered is updated in place, never duplicated (Part 8 reconnect).
    """
    employee = db.query(Employee).filter(Employee.id == employee_id).first()
    if not employee:
        raise ValueError(f"No employee found for id '{employee_id}'")

    device = db.query(Device).filter(Device.employee_id == employee.id).first()
    if device is None:
        device = Device(
            employee_id=employee.id,
            device_id=info.get("device_id") or f"DEV-{employee.id:04d}",
        )
        db.add(device)

    device.hostname = info.get("hostname") or device.hostname
    device.os_version = info.get("os_version") or device.os_version
    device.os_build = info.get("os_build") or device.os_build
    device.cpu_model = info.get("cpu_model") or device.cpu_model
    device.cpu_cores = info.get("cpu_cores") or device.cpu_cores
    device.ram_gb = info.get("ram_gb") or device.ram_gb
    device.disk_total_gb = info.get("disk_total_gb") or device.disk_total_gb
    device.disk_free_gb = info.get("disk_free_gb") or device.disk_free_gb
    device.ip_address = info.get("ip_address") or device.ip_address
    device.agent_version = info.get("agent_version") or device.agent_version
    device.status = "online"
    device.last_seen_at = _now()
    if device.first_seen_at is None:
        device.first_seen_at = _now()

    db.commit()
    db.refresh(device)
    return {
        "employee_id": employee.id,
        "device_id": device.device_id,
        "employee_name": employee.name,
        "employee_email": employee.email,
    }


def heartbeat(db: Session, device_id: str, metrics: Dict) -> Optional[Dict]:
    """Record a heartbeat from the agent, refreshing online status + health."""
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if device is None:
        return None

    device.last_seen_at = _now()
    device.status = "online"
    device.ip_address = metrics.get("ip_address") or device.ip_address
    if metrics.get("cpu_usage") is not None:
        device.last_cpu_usage = float(metrics["cpu_usage"])
    if metrics.get("ram_usage") is not None:
        device.last_ram_usage = float(metrics["ram_usage"])
    if metrics.get("disk_usage") is not None:
        device.last_disk_usage = float(metrics["disk_usage"])

    db.commit()
    db.refresh(device)
    return device_to_dict(device)


def get_device(db: Session, employee_id: int) -> Optional[Device]:
    return db.query(Device).filter(Device.employee_id == employee_id).first()


def is_online(device: Optional[Device], now: Optional[datetime] = None) -> bool:
    if device is None or device.last_seen_at is None:
        return False
    now = now or _now()
    return (now - device.last_seen_at).total_seconds() <= HEARTBEAT_TIMEOUT_SECONDS


def device_to_dict(device: Optional[Device]) -> Optional[Dict]:
    """Serialize a Device row for the API, including live online status."""
    if device is None:
        return None
    return {
        "device_id": device.device_id,
        "hostname": device.hostname,
        "os_version": device.os_version,
        "os_build": device.os_build,
        "cpu_model": device.cpu_model,
        "cpu_cores": device.cpu_cores,
        "ram_gb": device.ram_gb,
        "disk_total_gb": device.disk_total_gb,
        "disk_free_gb": device.disk_free_gb,
        "ip_address": device.ip_address,
        "agent_version": device.agent_version,
        "status": device.status,
        "online": is_online(device),
        "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
        "last_cpu_usage": device.last_cpu_usage,
        "last_ram_usage": device.last_ram_usage,
        "last_disk_usage": device.last_disk_usage,
    }


def compute_online_counts(db: Session) -> Dict:
    """Return {online, offline} totals across all registered devices."""
    now = _now()
    devices = db.query(Device).all()
    online = sum(1 for d in devices if is_online(d, now))
    offline = len(devices) - online
    return {"online": online, "offline": offline}
