"""
ThreatVista audit logging service.

Records security-relevant actions (login, logout, settings changes, alert
transitions, AI analysis triggers, report downloads, session revocation) into
the ``audit_logs`` table so the trail can be reviewed by an Administrator.
"""
from typing import Optional

from fastapi import Request
from sqlalchemy.orm import Session

from backend.models.database import AuditLog, User


def client_ip(request: Request) -> Optional[str]:
    """Best-effort client IP. Honours X-Forwarded-For when present."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def log_action(
    db: Session,
    user: Optional[User],
    action: str,
    resource: str,
    resource_id: Optional[str] = None,
    details: Optional[str] = None,
    ip: Optional[str] = None,
) -> AuditLog:
    """Persist one audit entry. Never raises — auditing must not break requests."""
    try:
        entry = AuditLog(
            user_id=user.id if user else None,
            username=user.username if user else None,
            role=user.role if user else None,
            action=action,
            resource=resource,
            resource_id=str(resource_id) if resource_id is not None else None,
            details=details,
            ip_address=ip,
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry
    except Exception:
        db.rollback()
        return None
