"""
Incident-based risk management.

Turns the AI pipeline's per-run risk result into *persistent* incident state:

- While an employee has an ACTIVE/INVESTIGATING incident, that incident's
  ``risk_score`` is the primary displayed score and is **monotonic** — it only
  ever rises when new evidence arrives and never auto-decays (enterprise EDR
  behaviour). New evidence is appended to the incident's timeline instead of
  creating a duplicate incident.
- With no active incident, a fresh incident is auto-created the first time the
  AI risk crosses the configured suspicious threshold.

The AI engine itself is untouched — this service only decides how a risk result
becomes (or merges into) a persistent Incident row. No commit happens here; the
caller commits once alongside its event/alert transaction.
"""
import json
from datetime import datetime

from sqlalchemy.orm import Session

from backend.models import database as models
from backend.services.config_service import get_thresholds

# After an incident is resolved/archived, wait this long (or require genuinely
# new events) before a recompute of old history is allowed to open a fresh one.
INCIDENT_REOPEN_COOLDOWN_MINUTES = 5

# Lifecycle states.
STATUS_ACTIVE = "ACTIVE"
STATUS_INVESTIGATING = "INVESTIGATING"
STATUS_RESOLVED = "RESOLVED"
STATUS_ARCHIVED = "ARCHIVED"


# --- Timeline helpers --------------------------------------------------------
def _get_timeline(incident) -> list:
    try:
        data = json.loads(incident.timeline_json or "[]")
        return data if isinstance(data, list) else []
    except Exception:
        return []


def append_timeline(incident, entry_type: str, title: str, detail: str = "") -> None:
    """Append one timeline entry in place (does not touch the DB session). Public
    so route handlers can record admin status changes on the same trail."""
    data = _get_timeline(incident)
    data.append({
        "ts": datetime.utcnow().isoformat(),
        "type": entry_type,
        "title": title,
        "detail": detail,
    })
    incident.timeline_json = json.dumps(data)


# --- Lifecycle transitions (admin actions) ----------------------------------
def resolve_incident(db: Session, incident, admin_name: str, reason: str) -> None:
    """Close an incident: RESOLVED, resolved-by/reason recorded, employee back to
    Safe with a zeroed live risk. Timeline entry preserved for history."""
    incident.status = STATUS_RESOLVED
    incident.active = False
    incident.resolved_at = datetime.utcnow()
    incident.resolved_by = admin_name
    incident.resolution_reason = reason
    incident.updated_at = datetime.utcnow()
    append_timeline(incident, "resolved", f"Incident resolved by {admin_name}", reason)
    emp = incident.employee
    if emp:
        emp.risk_score = 0
        emp.status = "Safe"


def archive_incident(db: Session, incident) -> None:
    """Move an incident into history. If it was still open, treat the archive as
    the close too (recorded_at) so the employee isn't left with a stuck score."""
    was_active = incident.active
    incident.status = STATUS_ARCHIVED
    incident.active = False
    incident.updated_at = datetime.utcnow()
    if was_active:
        incident.resolved_at = incident.resolved_at or datetime.utcnow()
    append_timeline(incident, "archived", "Incident archived", "")
    emp = incident.employee
    if emp:
        emp.risk_score = 0
        emp.status = "Safe"


# --- Classification ----------------------------------------------------------
def _severity_for_score(score: int, thresholds: dict) -> str:
    """Map a risk score to the incident severity band (mirrors RiskEngine)."""
    cfg = thresholds or {}
    high = cfg.get("high_risk_threshold", 75)
    suspicious = cfg.get("suspicious_threshold", 50)
    critical = min(100, high + 15)
    if score >= critical:
        return "Critical"
    if score >= high:
        return "High"
    if score >= suspicious:
        return "Medium"
    return "Low"


def _title_from_explanation(explanation: dict) -> str:
    """Derive an incident title from the AI's top risk reason."""
    reasons = explanation.get("reasons") or []
    if reasons:
        top = reasons[0]
        return top if len(top) <= 80 else top[:77] + "..."
    return "Suspicious Activity Detected"


def _usb_file_staging_pattern(result: dict) -> bool:
    """True when USB was used with meaningful file activity in the last 24h."""
    features = result.get("features") or {}
    return (
        features.get("usb_inserts_24h", 0) > 0
        and features.get("files_copied_24h", 0) >= 5
    )


def _usb_staging_title(result: dict, title_hint: str = None) -> str:
    """Prefer correlation name, then hint, then a default staging label."""
    if title_hint:
        return title_hint
    for corr in result.get("correlations") or []:
        name = corr.get("name")
        if name in ("USB Data Staging", "USB Mass Exfiltration"):
            return name
    return "USB Data Staging"


# --- Queries / serialization -------------------------------------------------
def get_active_incident(db: Session, employee_id: int):
    """The employee's latest ACTIVE/INVESTIGATING incident, if any."""
    return (
        db.query(models.Incident)
        .filter(
            models.Incident.employee_id == employee_id,
            models.Incident.active == True,
        )
        .order_by(models.Incident.created_at.desc(), models.Incident.id.desc())
        .first()
    )


def get_latest_incident(db: Session, employee_id: int):
    return (
        db.query(models.Incident)
        .filter(models.Incident.employee_id == employee_id)
        .order_by(models.Incident.created_at.desc(), models.Incident.id.desc())
        .first()
    )


def serialize(db: Session, incident, employee_name: str = None) -> dict:
    """Full incident dict for API responses / WebSocket broadcasts."""
    if incident is None:
        return None
    emp = incident.employee
    return {
        "id": incident.id,
        "employee_id": incident.employee_id,
        "employee": {
            "id": incident.employee_id,
            "name": employee_name or (emp.name if emp else ""),
        },
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "risk_score": incident.risk_score,
        "confidence": incident.confidence,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "resolved_by": incident.resolved_by,
        "resolution_reason": incident.resolution_reason,
        "active": incident.active,
        "timeline": _get_timeline(incident),
    }


# Event types that can re-open risk after a Manual Override / resolution.
# Heartbeats, system metrics, and process noise alone must not snap risk back.
_SECURITY_EVENT_TYPES = (
    "usb_insert",
    "usb_remove",
    "file_create",
    "file_delete",
    "file_modify",
    "file_move",
    "folder_create",
    "folder_move",
    "folder_delete",
    "network_upload",
)


# --- Core decision logic -----------------------------------------------------
def _stale_history_only(db: Session, employee_id: int) -> bool:
    """True when the employee's only "recent" evidence is pre-resolution history.

    After an analyst closes an incident (especially Manual Override / reset) we
    must not auto-open a new one or re-raise the live score just because a
    recompute of the same old events still looks risky. A fresh incident is
    only allowed when genuinely new *security-relevant* events arrived after
    the last one was closed.
    """
    latest = get_latest_incident(db, employee_id)
    if latest is None or latest.status not in (STATUS_RESOLVED, STATUS_ARCHIVED):
        return False
    closed_at = latest.resolved_at or latest.updated_at or latest.created_at
    if closed_at is None:
        return True
    newer = (
        db.query(models.Event)
        .filter(
            models.Event.employee_id == employee_id,
            models.Event.timestamp > closed_at,
            models.Event.event_type.in_(_SECURITY_EVENT_TYPES),
        )
        .count()
    )
    if newer > 0:
        return False
    return True


def list_active_incidents(db: Session, employee_id: int):
    """All ACTIVE/INVESTIGATING incidents for an employee (should usually be ≤1)."""
    return (
        db.query(models.Incident)
        .filter(
            models.Incident.employee_id == employee_id,
            models.Incident.active == True,
        )
        .order_by(models.Incident.created_at.desc(), models.Incident.id.desc())
        .all()
    )


def force_manual_override(db: Session, employee_id: int, admin_name: str) -> list:
    """Force employee to 0/Safe, resolve every open incident, and write a fresh
    RESOLVED Manual Override anchor so stale-history stays locked until new
    security evidence arrives. Returns the incidents that were resolved."""
    emp = db.query(models.Employee).filter(models.Employee.id == employee_id).first()
    if emp is None:
        return []

    resolved = []
    for active in list_active_incidents(db, employee_id):
        resolve_incident(db, active, admin_name, "Manual Override")
        resolved.append(active)

    emp.risk_score = 0
    emp.status = "Safe"

    now = datetime.utcnow()
    # Fresh anchor so closed_at is "now" even when there was no active incident.
    marker = models.Incident(
        employee_id=employee_id,
        title="Manual Risk Reset",
        severity="Low",
        status=STATUS_RESOLVED,
        risk_score=0,
        confidence=0,
        active=False,
        resolved_at=now,
        resolved_by=admin_name,
        resolution_reason="Manual Override",
        updated_at=now,
        timeline_json="[]",
    )
    db.add(marker)
    db.flush()
    append_timeline(marker, "resolved", f"Risk reset by {admin_name}", "Manual Override")
    return resolved


def apply_risk(
    db: Session,
    employee_id: int,
    result: dict,
    title_hint: str = None,
    evidence: list = None,
):
    """Reconcile one AI run against the employee's incident state.

    ``evidence`` is an optional list of ``{"title", "detail"}`` describing NEW
    suspicious activity that triggered this run (burst incidents, alerts). It is
    appended to the timeline and — only when present — may push the incident's
    risk score upward (never downward).

    Returns ``(event_type, incident)`` where event_type is ``incident_created``
    or ``incident_updated``, or ``None`` when nothing changed. Does NOT commit.
    """
    explanation = result.get("explanation", {})
    score = int(explanation.get("risk_score", 0))
    status = explanation.get("status", "Safe")
    confidence = int(explanation.get("confidence", 0))
    thresholds = get_thresholds(db)
    evidence = evidence or []

    active = get_active_incident(db, employee_id)
    if active is not None:
        changed = False
        for ev in evidence:
            append_timeline(active, "evidence", ev.get("title", "New evidence"), ev.get("detail", ""))
            changed = True
        if evidence and score > active.risk_score:
            append_timeline(active, "risk_increase", f"Risk increased: {active.risk_score} → {score}", "")
            active.risk_score = score
            active.severity = _severity_for_score(score, thresholds)
            active.confidence = max(active.confidence, confidence)
            active.updated_at = datetime.utcnow()
            changed = True
        elif evidence and confidence > active.confidence:
            active.confidence = confidence
            active.updated_at = datetime.utcnow()
            changed = True
        if changed:
            return ("incident_updated", active)
        return None

    usb_staging = _usb_file_staging_pattern(result)
    if status == "Safe" and not usb_staging:
        return None
    if _stale_history_only(db, employee_id):
        return None

    if usb_staging and status == "Safe":
        title = _usb_staging_title(result, title_hint)
        copies = (result.get("features") or {}).get("files_copied_24h", 0)
        staging_detail = f"USB activity with {copies} file operations in 24h"
        if not any(ev.get("title") == title for ev in evidence):
            evidence = list(evidence) + [{"title": title, "detail": staging_detail}]
    else:
        title = title_hint or _title_from_explanation(explanation)
    incident = models.Incident(
        employee_id=employee_id,
        title=title,
        severity=_severity_for_score(score, thresholds),
        status=STATUS_ACTIVE,
        risk_score=score,
        confidence=confidence,
        active=True,
        timeline_json="[]",
    )
    db.add(incident)
    db.flush()  # assign id so serialization works before the caller commits
    append_timeline(incident, "created", "Incident created", title)
    for ev in evidence:
        append_timeline(incident, "evidence", ev.get("title", "New evidence"), ev.get("detail", ""))
    return ("incident_created", incident)
