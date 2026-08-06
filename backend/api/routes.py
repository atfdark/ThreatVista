import csv
import io
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from backend.config import AGENT_API_KEY
from backend.database.connection import get_db
from backend.models import database as models
from backend.models.database import AuditLog, Session as SessionModel
from backend.services.event_service import EventService
from backend.services.alert_engine import RuleBasedAlertEngine
from backend.services import batch_service
from backend.services import incident_service
from backend.services.config_service import get_config, to_dict, update_config
from backend.services.audit_service import client_ip, log_action
from backend.services.agent_service import (
    register_device,
    heartbeat as agent_heartbeat,
    get_device,
    device_to_dict,
    compute_online_counts,
    create_enrollment_token,
    validate_enrollment_token,
    consume_enrollment_token,
    resolve_employee_by_email,
    is_online,
)
from backend.services.command_service import request_command, list_commands, ALLOWED_COMMANDS
from backend.reports.report_service import generate_report, REPORT_TYPES
from backend.websocket.manager import manager
from backend.auth import (
    create_access_token,
    create_session,
    decode_token,
    get_current_user,
    hash_password,
    revoke_session,
    verify_password,
    require_roles,
)

router = APIRouter()

# ---------------------------------------------------------------------------
# Login brute-force throttling (in-memory). Resets on process restart.
# ---------------------------------------------------------------------------
_LOGIN_ATTEMPTS = {}          # username -> {"fails": int, "locked_until": datetime}
LOGIN_MAX_FAILS = 5
LOGIN_LOCKOUT_MINUTES = 15

def _check_lockout(username: str):
    entry = _LOGIN_ATTEMPTS.get(username)
    if entry and entry.get("locked_until"):
        if entry["locked_until"] > datetime.utcnow():
            remaining = int((entry["locked_until"] - datetime.utcnow()).total_seconds() // 60) + 1
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed attempts. Try again in ~{remaining} minutes.",
            )
    return None

def _record_failed_login(username: str) -> bool:
    """Count a failed attempt. Returns True when it triggers the lockout."""
    entry = _LOGIN_ATTEMPTS.setdefault(username, {"fails": 0, "locked_until": None})
    entry["fails"] += 1
    if entry["fails"] >= LOGIN_MAX_FAILS:
        entry["locked_until"] = datetime.utcnow() + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
        entry["fails"] = 0
        return True
    return False

def _clear_lockout(username: str):
    _LOGIN_ATTEMPTS.pop(username, None)


def _run_ai(db: Session, employee_id: int):
    """Run the AI pipeline for an employee, applying persisted risk thresholds."""
    return batch_service.run_ai_for_employee(db, employee_id)


# --- Live risk persistence ---------------------------------------------------
# Recompute + store an employee's risk score whenever new telemetry arrives, so
# the Dashboard / Active Sessions risk reflects live activity instead of only
# what the Employee Profile page computes on demand. Throttled per employee to
# avoid running the ML pipeline on every single event.
RISK_RECOMPUTE_SECONDS = 30
_last_risk_recompute = {}  # employee_id -> datetime


def _recompute_risk_and_incidents(db: Session, employee_id: int, evidence: list = None,
                                  title_hint: str = None):
    """Recompute + persist an employee's live risk, correlation alerts and
    incident state, throttled to once per 30s per employee.

    Returns the incident change dict (``{"event_type", "incident"}``) when a
    lifecycle event occurred so async routes can broadcast it, else None. The
    caller owns the session (no session is opened here).
    """
    last = _last_risk_recompute.get(employee_id)
    if last and (datetime.utcnow() - last).total_seconds() < RISK_RECOMPUTE_SECONDS:
        return None
    _last_risk_recompute[employee_id] = datetime.utcnow()

    result = _run_ai(db, employee_id)
    batch_service.persist_risk_and_correlations(db, employee_id, result)
    change = incident_service.apply_risk(db, employee_id, result,
                                         title_hint=title_hint, evidence=evidence)
    db.commit()
    if change:
        return {"event_type": change[0], "incident": incident_service.serialize(db, change[1])}
    return None


def _build_analysis_response(db: Session, employee_id: int, result: dict) -> "AIAnalysisResponse":
    """AI response using the PRIMARY displayed score: the active incident's
    monotonic risk when one exists, otherwise the live explanation values."""
    explanation = result["explanation"]
    active_inc = incident_service.get_active_incident(db, employee_id)
    if active_inc:
        risk_score = active_inc.risk_score
        status = active_inc.severity
        confidence = active_inc.confidence
    else:
        risk_score = explanation["risk_score"]
        status = explanation["status"]
        confidence = explanation.get("confidence", 0)
    return AIAnalysisResponse(
        employee_id=employee_id,
        risk_score=risk_score,
        status=status,
        reasons=explanation["reasons"],
        recommendations=explanation["recommendations"],
        deviation=explanation.get("deviation", {}),
        model_anomaly=explanation.get("model_anomaly", False),
        model_score=explanation.get("model_score", 0),
        confidence=confidence,
        timestamp=result["timestamp"],
    )

# Pydantic Schemas
class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str       # email, e.g. john.doe@threatvista.com
    password: str
    name: str           # display name
    department: Optional[str] = "General"

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    username: str
    role: str
    name: Optional[str] = None

# Shared dependency: SOC staff only. Employee accounts authenticate but must
# not read SOC-wide data (other employees, alerts, settings, reports).
soc_only = require_roles("admin", "analyst", "auditor")

class EventCreate(BaseModel):
    employee_id: int
    timestamp: Optional[datetime] = None
    event_type: str
    filename: Optional[str] = None
    extension: Optional[str] = None
    size: Optional[str] = None
    folder: Optional[str] = None
    usb_status: Optional[str] = None
    network_upload: Optional[str] = None
    cpu_usage: Optional[float] = None
    ram_usage: Optional[float] = None
    details: Optional[str] = None

class EventResponse(BaseModel):
    id: int
    employee_id: int
    timestamp: datetime
    event_type: str
    filename: Optional[str]
    extension: Optional[str]
    size: Optional[str]
    folder: Optional[str]
    usb_status: Optional[str]
    network_upload: Optional[str]
    cpu_usage: Optional[float]
    ram_usage: Optional[float]
    details: Optional[str]

    class Config:
        from_attributes = True

class EventBatchRequest(BaseModel):
    """Payload for the bulk-ingest endpoint: a list of events from one agent
    batch, sent as a single HTTP request."""
    events: List[EventCreate]

class EmployeeBase(BaseModel):
    id: int
    name: str
    email: str
    department: str
    photo_url: Optional[str]
    risk_score: int
    status: str
    online: bool = False
    hostname: Optional[str] = None
    incident: Optional[dict] = None  # active incident, if any

    class Config:
        from_attributes = True

class BehaviorProfileSchema(BaseModel):
    working_hours_baseline: str
    avg_usb_inserts_per_day: float
    avg_file_copies_per_day: float
    avg_upload_mb_per_day: float

    class Config:
        from_attributes = True

class AlertSchema(BaseModel):
    id: int
    severity: str
    reason: str
    status: str
    timestamp: datetime

    class Config:
        from_attributes = True

class RiskHistorySchema(BaseModel):
    score: int
    recorded_at: datetime

    class Config:
        from_attributes = True

class EmployeeDetailResponse(BaseModel):
    id: int
    name: str
    email: str
    department: str
    photo_url: Optional[str]
    risk_score: int
    status: str
    behavior_profile: Optional[BehaviorProfileSchema]
    events: List[EventResponse]
    alerts: List[AlertSchema]
    risk_scores: List[RiskHistorySchema]
    ai_analysis: Optional[AIAnalysisResponse] = None
    device: Optional[dict] = None
    online: bool = False
    endpoint_health: Optional[dict] = None
    commands: List[dict] = []
    incident: Optional[dict] = None             # active incident (current + timeline)
    incident_history: List[dict] = []           # resolved / archived incidents

    class Config:
        from_attributes = True

class AlertDetailResponse(BaseModel):
    id: int
    severity: str
    reason: str
    status: str
    timestamp: datetime
    employee: EmployeeBase

    class Config:
        from_attributes = True

class AIAnalysisResponse(BaseModel):
    employee_id: int
    risk_score: float
    status: str
    reasons: List[str]
    recommendations: List[str]
    deviation: dict
    model_anomaly: bool
    model_score: float
    confidence: float = 0
    timestamp: str

class AlertStatusUpdate(BaseModel):
    status: str  # Active | Investigating | Resolved

class IncidentResolveRequest(BaseModel):
    reason: str

class DashboardResponse(BaseModel):
    total_employees: int
    active_alerts: int
    high_risk: int
    average_risk: float
    risk_distribution: List[dict]
    severity_distribution: List[dict]
    online_employees: int = 0
    offline_employees: int = 0

# --- Agent & device schemas ------------------------------------------------
class AgentRegisterRequest(BaseModel):
    # Token-based enrollment (current). Either this or the legacy email field
    # below must be supplied.
    enrollment_token: Optional[str] = None
    # Legacy path: kept so already-installed agents keep working until they
    # upgrade to the token-based flow.
    employee_email: Optional[str] = None
    device_id: Optional[str] = None
    hostname: Optional[str] = None
    os_version: Optional[str] = None
    os_build: Optional[str] = None
    cpu_model: Optional[str] = None
    cpu_cores: Optional[int] = None
    ram_gb: Optional[float] = None
    disk_total_gb: Optional[float] = None
    disk_free_gb: Optional[float] = None
    ip_address: Optional[str] = None
    agent_version: Optional[str] = None

class AgentHeartbeatRequest(BaseModel):
    device_id: str
    cpu_usage: Optional[float] = None
    ram_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    ip_address: Optional[str] = None

class CommandRequest(BaseModel):
    command: str  # one of ALLOWED_COMMANDS


def _employee_name_for(db: Session, username: str) -> Optional[str]:
    """Return the employee display name matching a login username/email, if any."""
    emp = db.query(models.Employee).filter(models.Employee.email == username).first()
    return emp.name if emp else None

# Auth Login Endpoint
@router.post("/auth/login", response_model=TokenResponse)
async def login(
    request: Request,
    payload: LoginRequest,
    db: Session = Depends(get_db),
):
    ip = client_ip(request)
    _check_lockout(payload.username)

    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        locked = _record_failed_login(payload.username)
        log_action(db, None, "login.failed", "auth", details=f"Failed login for '{payload.username}'", ip=ip)
        if locked:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed attempts. Account locked for {LOGIN_LOCKOUT_MINUTES} minutes.",
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    _clear_lockout(payload.username)
    token, jti, expires_at = create_access_token(user)
    create_session(db, user, jti, expires_at, ip=ip)
    log_action(db, user, "login", "auth", resource_id=str(user.id), details="User login", ip=ip)

    # Push the sign-in to every open SOC dashboard so the admin sees it live.
    await manager.broadcast({
        "type": "new_login",
        "data": {
            "username": user.username,
            "role": user.role,
            "ip": ip,
            "at": datetime.utcnow().isoformat(),
        },
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "role": user.role,
        "name": _employee_name_for(db, user.username),
    }


@router.post("/auth/register", response_model=TokenResponse)
async def register(
    request: Request,
    payload: RegisterRequest,
    db: Session = Depends(get_db),
):
    """Self-registration for employees. Creates a `role="employee"` user (and a
    matching Employee directory row if needed), then auto-logs-in.
    """
    ip = client_ip(request)
    username = payload.username.strip().lower()
    if len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    if not username:
        raise HTTPException(status_code=400, detail="Username/email is required")

    if db.query(models.User).filter(models.User.username == username).first():
        raise HTTPException(status_code=409, detail="An account with this email already exists")

    user = models.User(
        username=username,
        password_hash=hash_password(payload.password),
        role="employee",
    )
    db.add(user)

    # Add to the employee directory so the person is visible/monitorable in SOC.
    if db.query(models.Employee).filter(models.Employee.email == username).first() is None:
        emp = models.Employee(
            name=payload.name,
            email=username,
            department=payload.department or "General",
            risk_score=0,
            status="Normal",
        )
        db.add(emp)
        db.flush()  # get emp.id before creating the DNA row
        db.add(models.BehaviorProfile(
            employee_id=emp.id,
            working_hours_baseline="09:00 - 17:00",
            avg_usb_inserts_per_day=0.0,
            avg_file_copies_per_day=0.0,
            avg_upload_mb_per_day=0.0,
        ))

    db.commit()
    db.refresh(user)
    log_action(db, user, "register", "auth", resource_id=str(user.id),
               details=f"Employee account created for '{username}'", ip=ip)

    token, jti, expires_at = create_access_token(user)
    create_session(db, user, jti, expires_at, ip=ip)
    log_action(db, user, "login", "auth", resource_id=str(user.id), details="User login", ip=ip)

    await manager.broadcast({
        "type": "new_login",
        "data": {
            "username": user.username,
            "role": user.role,
            "ip": ip,
            "at": datetime.utcnow().isoformat(),
        },
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "role": user.role,
        "name": payload.name,
    }

@router.post("/auth/logout")
def logout(
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke the current session server-side so the token stops working."""
    token = request.headers.get("authorization", "").replace("Bearer ", "")
    try:
        payload = decode_token(token)
        revoke_session(db, payload.get("jti"))
    except Exception:
        pass
    log_action(
        db, current_user, "logout", "auth",
        resource_id=str(current_user.id), details="User logout", ip=client_ip(request),
    )

    # When the logged-out user is an employee with a registered endpoint, mark
    # their device offline in the UI. (If the agent is still running it will
    # re-heartbeat and come back online within ~30s.)
    emp = db.query(models.Employee).filter(models.Employee.email == current_user.username).first()
    if emp:
        dev = db.query(models.Device).filter(models.Device.employee_id == emp.id).first()
        if dev:
            dev.last_seen_at = None
            dev.status = "offline"
            db.commit()

    return {"message": f"{current_user.username} logged out successfully"}


# --- Session management -----------------------------------------------------
@router.get("/auth/sessions")
def list_sessions(
    user_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """List active/revoked sessions. Admins may filter by any user_id."""
    target_id = user_id or current_user.id
    if target_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    sessions = (
        db.query(SessionModel)
        .filter(SessionModel.user_id == target_id)
        .order_by(SessionModel.created_at.desc())
        .all()
    )
    return [
        {
            "id": s.id,
            "user_id": s.user_id,
            "jti": s.jti,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "expires_at": s.expires_at.isoformat() if s.expires_at else None,
            "revoked": s.revoked,
            "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None,
            "ip_address": s.ip_address,
        }
        for s in sessions
    ]


@router.delete("/auth/sessions/{session_id}")
def delete_session(
    session_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Revoke a session. Users may revoke their own; admins/analysts any."""
    session = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.user_id != current_user.id and current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    owner = db.query(models.User).filter(models.User.id == session.user_id).first()
    if not session.revoked:
        session.revoked = True
        db.commit()
        log_action(
            db, current_user, "session.revoke", "session",
            resource_id=str(session.id),
            details=f"Revoked session for '{owner.username if owner else session.user_id}'",
            ip=client_ip(request),
        )
    return {"message": f"Session {session_id} revoked"}

@router.get("/auth/me")
def get_me(current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
        "name": _employee_name_for(db, current_user.username)
    }


# Health Check
@router.get("/status")
def get_status():
    return {
        "status": "ThreatVista Backend Running",
        "database": "SQLite Connected",
        "engine": "FastAPI",
        "timestamp": datetime.utcnow()
    }


# Dashboard
@router.get("/dashboard", response_model=DashboardResponse)
def get_dashboard(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(soc_only),
):
    employees = db.query(models.Employee).all()
    alerts = db.query(models.Alert).all()

    risk_scores = []
    for emp in employees:
        result = _run_ai(db, emp.id)
        explanation = result["explanation"]
        emp.risk_score = int(explanation["risk_score"])
        emp.status = explanation["status"]
        # Keep incident state consistent with the fresh assessment (never lowers).
        incident_service.apply_risk(db, emp.id, result)
        active_inc = incident_service.get_active_incident(db, emp.id)
        # Primary displayed score: the incident's monotonic risk when one is active.
        primary = active_inc.risk_score if active_inc else int(explanation["risk_score"])
        risk_scores.append(primary)
    db.commit()

    risk_dist = {"Low (0-30)": 0, "Medium (31-60)": 0, "High (61-80)": 0, "Critical (81-100)": 0}
    for score in risk_scores:
        if score <= 30:
            risk_dist["Low (0-30)"] += 1
        elif score <= 60:
            risk_dist["Medium (31-60)"] += 1
        elif score <= 80:
            risk_dist["High (61-80)"] += 1
        else:
            risk_dist["Critical (81-100)"] += 1

    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
    for alert in alerts:
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1

    active_alerts = sum(1 for a in alerts if a.status == "Active")
    high_risk = sum(1 for s in risk_scores if s > 75)
    avg_risk = int(sum(risk_scores) / len(risk_scores)) if risk_scores else 0

    online_counts = compute_online_counts(db)

    return {
        "total_employees": len(employees),
        "active_alerts": active_alerts,
        "high_risk": high_risk,
        "average_risk": avg_risk,
        "risk_distribution": [{"range": k, "count": v} for k, v in risk_dist.items()],
        "severity_distribution": [{"severity": k, "count": v} for k, v in severity_counts.items()],
        "online_employees": online_counts["online"],
        "offline_employees": online_counts["offline"],
    }


# Employees
@router.get("/employees", response_model=List[EmployeeBase])
def get_employees(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(soc_only),
):
    employees = db.query(models.Employee).all()
    for emp in employees:
        device = get_device(db, emp.id)
        emp.online = bool(device and device_to_dict(device).get("online"))
        emp.hostname = device.hostname if device else None
        emp.incident = incident_service.serialize(db, incident_service.get_active_incident(db, emp.id))
    return employees

@router.get("/employees/{employee_id}", response_model=EmployeeDetailResponse)
def get_employee_detail(
    employee_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(soc_only),
):
    employee = db.query(models.Employee).filter(models.Employee.id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    result = _run_ai(db, employee_id)
    explanation = result["explanation"]
    # Persist live DNA + risk history + correlation alerts so Behavior DNA and
    # Historical Risk Progression stay current for self-registered employees
    # who never got a seeded profile.
    batch_service.persist_risk_and_correlations(db, employee_id, result)
    employee.risk_score = int(explanation["risk_score"])
    employee.status = explanation["status"]
    incident_service.apply_risk(db, employee_id, result)
    db.commit()

    # Reload relationships after persistence so the response reflects the
    # freshly written Behavior DNA and risk history.
    db.refresh(employee)
    employee.behavior_profile = (
        db.query(models.BehaviorProfile)
        .filter(models.BehaviorProfile.employee_id == employee_id)
        .first()
    )
    # Cap the stream sent to the UI — AI already ran over the full history.
    all_events = sorted(employee.events, key=lambda x: x.timestamp or datetime.min, reverse=True)
    employee.events = all_events[:100]
    employee.risk_scores = sorted(
        db.query(models.RiskScore)
        .filter(models.RiskScore.employee_id == employee_id)
        .order_by(models.RiskScore.recorded_at.asc())
        .all(),
        key=lambda x: x.recorded_at,
    )
    employee.ai_analysis = _build_analysis_response(db, employee_id, result)

    # EDR device + online status + endpoint health + command history
    device = get_device(db, employee_id)
    employee.device = device_to_dict(device)
    employee.online = bool(device and device_to_dict(device).get("online"))
    if device:
        employee.endpoint_health = {
            "cpu_usage": device.last_cpu_usage,
            "ram_usage": device.last_ram_usage,
            "disk_usage": device.last_disk_usage,
            "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
            "agent_version": device.agent_version,
        }
    else:
        employee.endpoint_health = None
    employee.commands = list_commands(db, employee_id, limit=10)

    # Current incident + resolution history (full timeline preserved in both).
    employee.incident = incident_service.serialize(
        db, incident_service.get_active_incident(db, employee_id)
    )
    employee.incident_history = [
        incident_service.serialize(db, inc)
        for inc in (
            db.query(models.Incident)
            .filter(
                models.Incident.employee_id == employee_id,
                models.Incident.status.in_([
                    incident_service.STATUS_RESOLVED,
                    incident_service.STATUS_ARCHIVED,
                ]),
            )
            .order_by(models.Incident.created_at.desc(), models.Incident.id.desc())
            .all()
        )
    ]

    return employee


@router.get("/endpoints")
def get_endpoints(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """List connected endpoints (registered devices) joined with their employee.

    Powers the "Active Sessions" dashboard: every device, its live health from the
    latest heartbeat, and how many telemetry events the employee produced in the
    last hour. Sorted online-first so active machines lead the page.
    """
    devices = db.query(models.Device).all()
    cutoff = datetime.utcnow() - timedelta(hours=1)

    result = []
    for dev in devices:
        emp = dev.employee
        recent_count = (
            db.query(models.Event)
            .filter(
                models.Event.employee_id == emp.id,
                models.Event.timestamp >= cutoff,
            )
            .count()
        )
        result.append({
            "employee": {
                "id": emp.id,
                "name": emp.name,
                "email": emp.email,
                "department": emp.department,
                "risk_score": emp.risk_score,
                "status": emp.status,
            },
            "device": device_to_dict(dev),
            "recent_event_count": recent_count,
        })

    result.sort(
        key=lambda r: (
            not (r["device"] or {}).get("online"),
            r["employee"]["name"].lower(),
        )
    )
    return result


# Events
@router.post("/events", response_model=EventResponse)
async def create_event(
    event: EventCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    # When an agent key is configured, telemetry must authenticate with it.
    if AGENT_API_KEY and request.headers.get("x-agent-key") != AGENT_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid agent key",
        )
    event_data = event.model_dump()
    created_event = EventService.create_event(db, event_data)

    alerts = RuleBasedAlertEngine.evaluate_event(db, created_event)
    db.commit()

    await manager.broadcast({
        "type": "new_event",
        "data": {
            "id": created_event.id,
            "employee_id": created_event.employee_id,
            "event_type": created_event.event_type,
            "timestamp": created_event.timestamp.isoformat(),
            "details": created_event.details
        }
    })

    if alerts:
        for alert in alerts:
            emp = db.query(models.Employee).filter(models.Employee.id == alert.employee_id).first()
            await manager.broadcast({
                "type": "new_alert",
                "data": {
                    "id": alert.id,
                    "employee_id": alert.employee_id,
                    "employee": {"id": alert.employee_id, "name": emp.name if emp else ""},
                    "severity": alert.severity,
                    "reason": alert.reason,
                    "status": alert.status,
                    "timestamp": alert.timestamp.isoformat()
                }
            })

    # Refresh the employee's stored risk + incident state (throttled per
    # employee) and broadcast any incident lifecycle change immediately, so the
    # dashboard reflects single-event activity without a page refresh.
    evidence = []
    if created_event.details:
        evidence.append({
            "title": created_event.event_type.replace("_", " ").title(),
            "detail": created_event.details,
        })
    if alerts:
        for alert in alerts:
            evidence.append({"title": f"Alert: {alert.reason}", "detail": alert.severity})

    change = _recompute_risk_and_incidents(
        db, created_event.employee_id,
        evidence=evidence,
        title_hint=alerts[0].reason if alerts else None,
    )
    if change:
        await manager.broadcast({"type": change["event_type"], "data": change["incident"]})

    return created_event


@router.post("/events/batch")
async def create_event_batch(
    payload: EventBatchRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Bulk-ingest one agent batch in a single transaction.

    FAST PATH: inserts events, evaluates batch alerts, and broadcasts
    the WebSocket message IMMEDIATELY — the dashboard sees all events
    within ~1 second. The heavy AI pipeline (risk scoring, incident
    lifecycle) runs in a background thread so it never blocks the
    response or the live feed.
    """
    if AGENT_API_KEY and request.headers.get("x-agent-key") != AGENT_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid agent key",
        )
    if not payload.events:
        return {"ingested": 0, "incidents": 0}

    event_data = [evt.model_dump() for evt in payload.events]

    # Fast path: insert + broadcast immediately (no AI pipeline).
    result = batch_service.process_batch_fast(db, event_data)

    # Broadcast events to all connected dashboards RIGHT NOW.
    await manager.broadcast({"type": "batch_event", "data": result})

    # Kick off the heavy AI pipeline in a background thread so risk scores,
    # incidents, and correlation alerts still get computed — just not blocking
    # the HTTP response or the live event feed.
    emp_ids = {evt.get("employee_id", 1) for evt in event_data}
    batch_service.run_ai_background(
        emp_ids,
        result.get("events", []),
        result.get("alerts", []),
    )

    return {"ingested": len(event_data), "incidents": len(result.get("incidents", []))}

@router.get("/events", response_model=List[EventResponse])
def get_events(
    skip: int = 0,
    limit: int = 100,
    employee_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(soc_only),
):
    if employee_id:
        events = EventService.get_events_by_employee(db, employee_id, skip, limit)
    else:
        events = EventService.get_events(db, skip, limit)
    return events

@router.get("/events/recent", response_model=List[EventResponse])
def get_recent_events(
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    events = EventService.get_recent_events(db, limit)
    return events


# Alerts
@router.get("/alerts", response_model=List[AlertDetailResponse])
def get_alerts(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(soc_only),
):
    alerts = db.query(models.Alert).all()
    alerts = sorted(alerts, key=lambda x: x.timestamp, reverse=True)
    return alerts


@router.patch("/alerts/{alert_id}", response_model=AlertDetailResponse)
async def update_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin", "analyst")),
):
    """Persist alert lifecycle transitions (Active -> Investigating -> Resolved)."""
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    valid_statuses = ("Active", "Investigating", "Resolved")
    if payload.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"status must be one of {valid_statuses}")

    old_status = alert.status
    alert.status = payload.status
    db.commit()
    db.refresh(alert)

    log_action(
        db, current_user, "alert.update", "alert",
        resource_id=str(alert.id),
        details=f"Alert status '{old_status}' -> '{alert.status}'",
        ip=client_ip(request),
    )

    await _broadcast_alert_update(alert)
    return alert


async def _broadcast_alert_update(alert):
    """Push an alert status change to connected dashboards."""
    await manager.broadcast({
        "type": "alert_updated",
        "data": {
            "id": alert.id,
            "severity": alert.severity,
            "reason": alert.reason,
            "status": alert.status,
            "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
        },
    })


# Audit logs
@router.get("/audit-logs")
def get_audit_logs(
    action: Optional[str] = None,
    user_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin")),
):
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    logs = query.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit).all()
    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "username": log.username,
            "role": log.role,
            "action": log.action,
            "resource": log.resource,
            "resource_id": log.resource_id,
            "details": log.details,
            "ip_address": log.ip_address,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in logs
    ]


# AI Analysis
@router.post("/ai/analyze/{employee_id}", response_model=AIAnalysisResponse)
async def analyze_employee(
    employee_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin", "analyst")),
):
    employee = db.query(models.Employee).filter(models.Employee.id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    result = _run_ai(db, employee_id)
    explanation = result["explanation"]

    employee.risk_score = int(explanation["risk_score"])
    employee.status = explanation["status"]
    change = incident_service.apply_risk(db, employee_id, result)
    db.commit()

    log_action(
        db, current_user, "ai.analyze", "employee",
        resource_id=str(employee_id),
        details=f"Risk score {employee.risk_score} ({employee.status})",
        ip=client_ip(request),
    )

    if change:
        await manager.broadcast({"type": change[0], "data": incident_service.serialize(db, change[1])})

    return _build_analysis_response(db, employee_id, result)

@router.get("/ai/analysis/{employee_id}", response_model=AIAnalysisResponse)
async def get_ai_analysis(
    employee_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(soc_only),
):
    employee = db.query(models.Employee).filter(models.Employee.id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    result = _run_ai(db, employee_id)
    explanation = result["explanation"]

    employee.risk_score = int(explanation["risk_score"])
    employee.status = explanation["status"]
    incident_service.apply_risk(db, employee_id, result)
    db.commit()

    return _build_analysis_response(db, employee_id, result)


# ---------------------------------------------------------------------------
# Incidents (persistent, lifecycle-driven) -----------------------------------
# ---------------------------------------------------------------------------
def _get_incident_or_404(db: Session, incident_id: int):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/incidents")
def get_incidents(
    status: Optional[str] = Query(None, description="Filter by incident status"),
    employee_id: Optional[int] = Query(None, description="Filter by employee"),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(soc_only),
):
    """All incidents, newest first, with optional status/employee filters."""
    query = db.query(models.Incident)
    if status:
        query = query.filter(models.Incident.status == status)
    if employee_id:
        query = query.filter(models.Incident.employee_id == employee_id)
    incidents = query.order_by(
        models.Incident.created_at.desc(), models.Incident.id.desc()
    ).all()
    return [incident_service.serialize(db, inc) for inc in incidents]


@router.get("/incidents/{incident_id}")
def get_incident_detail(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(soc_only),
):
    """Single incident detail (includes the full timeline + resolution info)."""
    return incident_service.serialize(db, _get_incident_or_404(db, incident_id))


@router.post("/incidents/{incident_id}/investigate")
async def investigate_incident(
    incident_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin", "analyst")),
):
    """Mark an ACTIVE incident as INVESTIGATING by an analyst."""
    incident = _get_incident_or_404(db, incident_id)
    if incident.status != incident_service.STATUS_ACTIVE:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot investigate an incident in status '{incident.status}'",
        )
    incident.status = incident_service.STATUS_INVESTIGATING
    incident.updated_at = datetime.utcnow()
    incident_service.append_timeline(
        incident,
        "status_change",
        f"Investigation started by {current_user.username}",
        "",
    )
    log_action(
        db, current_user, "incident.investigate", "incident",
        resource_id=str(incident.id),
        details=f"Investigation started: {incident.title}",
        ip=client_ip(request),
    )
    db.commit()
    data = incident_service.serialize(db, incident)
    await manager.broadcast({"type": "incident_updated", "data": data})
    return data


@router.post("/incidents/{incident_id}/resolve")
async def resolve_incident(
    incident_id: int,
    payload: IncidentResolveRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin", "analyst")),
):
    """Resolve an incident with an analyst-provided reason. The employee is
    returned to Safe (live risk 0) and the incident moves to history with its
    full timeline preserved."""
    incident = _get_incident_or_404(db, incident_id)
    if incident.status == incident_service.STATUS_ARCHIVED:
        raise HTTPException(status_code=400, detail="Archived incidents cannot be resolved")
    incident_service.resolve_incident(db, incident, current_user.username, payload.reason)
    log_action(
        db, current_user, "incident.resolve", "incident",
        resource_id=str(incident.id),
        details=f"Resolved Incident / {payload.reason}",
        ip=client_ip(request),
    )
    db.commit()
    data = incident_service.serialize(db, incident)
    await manager.broadcast({"type": "incident_resolved", "data": data})
    return data


@router.post("/incidents/{incident_id}/archive")
async def archive_incident(
    incident_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin")),
):
    """Move an incident into history (admin only)."""
    incident = _get_incident_or_404(db, incident_id)
    if incident.status == incident_service.STATUS_ARCHIVED:
        raise HTTPException(status_code=400, detail="Incident is already archived")
    incident_service.archive_incident(db, incident)
    log_action(
        db, current_user, "incident.archive", "incident",
        resource_id=str(incident.id),
        details=f"Archived incident: {incident.title}",
        ip=client_ip(request),
    )
    db.commit()
    data = incident_service.serialize(db, incident)
    await manager.broadcast({"type": "incident_archived", "data": data})
    return data


@router.post("/employees/{employee_id}/reset-risk")
async def reset_employee_risk(
    employee_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin")),
):
    """Admin-only manual override: force an employee back to 0 / Safe. If an
    ACTIVE incident exists it is resolved as a 'Manual Override' so the primary
    displayed score follows the override. Audited via incident.reset_risk."""
    employee = db.query(models.Employee).filter(models.Employee.id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    employee.risk_score = 0
    employee.status = "Safe"
    active = incident_service.get_active_incident(db, employee_id)
    if active:
        incident_service.resolve_incident(db, active, current_user.username, "Manual Override")

    log_action(
        db, current_user, "incident.reset_risk", "employee",
        resource_id=str(employee_id),
        details="Reset Risk / Manual Override",
        ip=client_ip(request),
    )
    db.commit()

    if active:
        await manager.broadcast({
            "type": "incident_resolved",
            "data": incident_service.serialize(db, active),
        })
    return {
        "message": "Employee risk reset",
        "employee": {"id": employee.id, "risk_score": 0, "status": "Safe"},
        "incident": incident_service.serialize(db, active) if active else None,
    }


# System Settings (persisted config that drives the risk engine)
@router.get("/settings")
def get_settings(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return to_dict(get_config(db))

@router.put("/settings")
def put_settings(
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin", "analyst")),
):
    updated = update_config(db, payload)
    log_action(
        db, current_user, "settings.update", "settings",
        details=str({k: payload[k] for k in payload if k in ("high_risk_threshold", "suspicious_threshold", "dna_window_days")}),
        ip=client_ip(request),
    )
    return to_dict(updated)


# ---------------------------------------------------------------------------
# Reports (downloadable exports)
# ---------------------------------------------------------------------------
@router.get("/reports/{report_type}")
def get_report(
    report_type: str,
    format: str = Query("json", pattern="^(json|csv|html)$"),
    start: Optional[str] = None,
    end: Optional[str] = None,
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(soc_only),
):
    """Generate and download a report (daily_threat, weekly_activity, ...)."""
    if report_type not in REPORT_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown report type. Valid: {', '.join(REPORT_TYPES)}",
        )
    try:
        report = generate_report(db, report_type, start=start, end=end)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    log_action(
        db, current_user, "report.download", "report",
        resource_id=report_type, details=f"format={format}",
        ip=client_ip(request),
    )

    if format == "json":
        return report

    if format == "csv":
        return _render_report_csv(report, report_type)

    return _render_report_html(report)


def _render_report_csv(report: dict, report_type: str) -> StreamingResponse:
    """Serialize a report's rows into a CSV attachment."""
    rows = report.get("rows", [])
    fieldnames = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    if not fieldnames:
        fieldnames = ["item"]

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    buffer.seek(0)

    filename = f"threatvista_{report_type}_{datetime.utcnow().strftime('%Y%m%d')}.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _render_report_html(report: dict) -> HTMLResponse:
    """Render a self-contained printable HTML report (browsers can save to PDF)."""
    summary = report.get("summary", {})
    rows = report.get("rows", [])
    trends = report.get("trends", [])
    recommendations = report.get("recommendations", [])

    summary_html = "".join(
        f'<div class="stat"><span class="label">{k.replace("_", " ")}</span>'
        f'<span class="value">{v}</span></div>'
        for k, v in summary.items()
    )
    rows_html = ""
    if rows:
        columns = list(rows[0].keys())
        header = "".join(f"<th>{c.replace('_', ' ')}</th>" for c in columns)
        body = "".join(
            "<tr>" + "".join(f"<td>{row.get(c, '')}</td>" for c in columns) + "</tr>"
            for row in rows
        )
        rows_html = f"<table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table>"
    else:
        rows_html = "<p class='empty'>No rows for this period.</p>"

    trends_html = "".join(
        f"<tr><td>{t.get('date', '')}</td><td>{t.get('event_count', 0)}</td>"
        f"<td>{t.get('avg_risk', 0)}</td><td>{t.get('new_alerts', 0)}</td></tr>"
        for t in trends
    )
    recs_html = "".join(f"<li>{r}</li>" for r in recommendations) or "<li>None</li>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>{report.get('title', 'ThreatVista Report')}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #0f172a; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  .meta {{ color: #64748b; font-size: 12px; margin-bottom: 24px; }}
  .stats {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 24px; }}
  .stat {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 10px 16px; min-width: 120px; }}
  .stat .label {{ display: block; color: #64748b; font-size: 10px; text-transform: uppercase; letter-spacing: .5px; }}
  .stat .value {{ font-size: 20px; font-weight: 700; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 12px; margin-bottom: 24px; }}
  th, td {{ border: 1px solid #e2e8f0; padding: 6px 10px; text-align: left; }}
  th {{ background: #f8fafc; text-transform: uppercase; font-size: 10px; letter-spacing: .5px; }}
  h2 {{ font-size: 15px; margin: 20px 0 8px; }}
  .empty {{ color: #94a3b8; font-style: italic; }}
  ul {{ font-size: 12px; line-height: 1.7; }}
</style>
</head>
<body>
  <h1>{report.get('title', 'ThreatVista Report')}</h1>
  <div class="meta">Period: {report.get('period', '')} &middot; Generated: {report.get('generated_at', '')}</div>
  <div class="stats">{summary_html}</div>
  <h2>Detail</h2>
  {rows_html}
  <h2>Daily Risk Trend</h2>
  <table><thead><tr><th>Date</th><th>Events</th><th>Avg Risk</th><th>New Alerts</th></tr></thead>
  <tbody>{trends_html or "<tr><td colspan='4'>No data.</td></tr>"}</tbody></table>
  <h2>Recommendations</h2>
  <ul>{recs_html}</ul>
</body>
</html>"""
    return HTMLResponse(content=html, media_type="text/html")


# ---------------------------------------------------------------------------
# Endpoint agent (token-based enrollment, device registration & heartbeat)
# & remote commands
# ---------------------------------------------------------------------------
@router.post("/agent/enroll")
def agent_enroll(
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Issue a one-time enrollment token for the logged-in employee's device.

    Employee-only. The employee clicks "Connect This Device" on their profile,
    the page calls this endpoint and downloads ``threatvista-agent-config.json``
    containing the token + the backend URL (derived from the request the browser
    already used — no manual IP/email typing).
    """
    if current_user.role != "employee":
        raise HTTPException(status_code=403, detail="Only employees can enroll a device")
    employee = resolve_employee_by_email(db, current_user.username)
    if not employee:
        raise HTTPException(status_code=404, detail="Employee profile not found for this account")

    # The browser reached us at request.base_url (scheme + host + port). That is
    # exactly the address the endpoint agent on the same LAN must use, so the
    # employee never has to type a backend IP.
    backend_url = str(request.base_url).rstrip("/")
    data = create_enrollment_token(db, employee, backend_url)
    log_action(
        db, current_user, "agent.enroll", "employee",
        resource_id=str(employee.id),
        details=f"Enrollment token issued for {employee.email}",
        ip=client_ip(request),
    )
    return data


@router.post("/agent/register")
async def agent_register(
    payload: AgentRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Register an endpoint agent's device.

    Current flow: the agent presents the ``enrollment_token`` it read from
    ``threatvista-agent-config.json``. The backend validates it (not expired /
    not used / known), resolves the employee, registers/updates their Device and
    consumes the token. Legacy flow (``employee_email``) is still accepted so
    already-installed agents keep working. Broadcasts ``device_connected`` so
    Dashboard / Employee page / Active Sessions update instantly.
    """
    if AGENT_API_KEY and request.headers.get("x-agent-key") != AGENT_API_KEY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid agent key")

    info = payload.model_dump()
    info.pop("enrollment_token", None)
    info.pop("employee_email", None)

    token_auth = False
    try:
        if payload.enrollment_token:
            token_auth = True  # set before validation so rejected tokens -> 401
            employee = validate_enrollment_token(db, payload.enrollment_token)
        else:
            employee = resolve_employee_by_email(db, payload.employee_email or "")
            if employee is None:
                raise ValueError(f"No employee found for email '{payload.employee_email}'")

        result = register_device(db, employee.id, info)

        # Only consume the token after the device actually registered, so a
        # failed registration never burns an otherwise-valid token.
        if token_auth:
            consume_enrollment_token(db, payload.enrollment_token, device_id=result["device_id"])

        # Live update: Dashboard, Employee page and Active Sessions all refresh
        # on this broadcast so the device shows Online without a page reload.
        device = get_device(db, employee.id)
        await manager.broadcast({
            "type": "device_connected",
            "data": {
                "device": device_to_dict(device),
                "employee": {"id": employee.id, "name": employee.name},
            },
        })
        return {"registered": True, **result}
    except ValueError as exc:
        # Token failures (unknown / used / expired) are authentication failures
        # -> 401. Legacy email failures stay 404 for backward compatibility.
        raise HTTPException(
            status_code=401 if token_auth else 404,
            detail=str(exc),
        )


@router.get("/agent/status")
def agent_status(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Current device status for the logged-in employee (employee-only).

    Lets the employee profile page render "This Device / Status: Online or
    Disconnected" without needing SOC-only employee endpoints.
    """
    if current_user.role != "employee":
        raise HTTPException(status_code=403, detail="Only employees can query their device status")
    employee = resolve_employee_by_email(db, current_user.username)
    if not employee:
        raise HTTPException(status_code=404, detail="Employee profile not found for this account")
    device = get_device(db, employee.id)
    return {
        "employee_id": employee.id,
        "employee_name": employee.name,
        "employee_email": employee.email,
        "device": device_to_dict(device),
        "online": is_online(device),
    }


@router.post("/agent/heartbeat")
def agent_heartbeat_endpoint(
    payload: AgentHeartbeatRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Heartbeat from an endpoint agent. Refreshes online status + health."""
    if AGENT_API_KEY and request.headers.get("x-agent-key") != AGENT_API_KEY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid agent key")
    updated = agent_heartbeat(db, payload.device_id, payload.model_dump())
    if updated is None:
        raise HTTPException(status_code=404, detail=f"Unknown device_id '{payload.device_id}'")
    return {"heartbeat": "ok", "device": updated}


@router.post("/employees/{employee_id}/commands")
def create_command(
    employee_id: int,
    payload: CommandRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin", "analyst")),
):
    """Issue a (simulated) remote command to an endpoint agent."""
    if payload.command not in ALLOWED_COMMANDS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown command '{payload.command}'. Valid: {', '.join(ALLOWED_COMMANDS)}",
        )
    try:
        cmd = request_command(db, employee_id, payload.command, requested_by=current_user.username)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    log_action(
        db, current_user, "command.issue", "employee",
        resource_id=str(employee_id),
        details=f"Command '{payload.command}' (simulated)",
        ip=client_ip(request),
    )
    return cmd


@router.get("/employees/{employee_id}/commands")
def get_commands(
    employee_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(soc_only),
):
    """List recent commands issued to an employee's endpoint."""
    return list_commands(db, employee_id, limit=20)
