import csv
import io
from collections import defaultdict
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from backend.config import AGENT_API_KEY, PUBLIC_URL
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
from backend.services import action_request_service
from backend.services import user_behavior_service
from backend.services import digital_twin_service
from backend.reports.report_service import generate_report, REPORT_TYPES
from backend.websocket.manager import manager
from ai.role_config import get_role_config, get_all_role_baselines, get_supported_roles
from ai.sensitive_scanner import SensitiveAssetScanner
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
    evidence = list(evidence or [])
    for corr in result.get("correlations") or []:
        evidence.append({"title": corr["name"], "detail": corr.get("reason", "")})
    if not title_hint and result.get("correlations"):
        title_hint = result["correlations"][0]["name"]
    change = incident_service.apply_risk(db, employee_id, result,
                                         title_hint=title_hint, evidence=evidence)
    db.commit()
    if change:
        return {"event_type": change[0], "incident": incident_service.serialize(db, change[1])}
    return None


def _build_analysis_response(db: Session, employee_id: int, result: dict) -> "AIAnalysisResponse":
    """AI response using the PRIMARY displayed score: active incident when open,
    otherwise the persisted employee row (respects manual reset to 0/Safe)."""
    explanation = result["explanation"]
    active_inc = incident_service.get_active_incident(db, employee_id)
    emp = db.query(models.Employee).filter(models.Employee.id == employee_id).first()
    if active_inc:
        risk_score = active_inc.risk_score
        status = active_inc.severity
        confidence = active_inc.confidence
    elif emp is not None:
        risk_score = emp.risk_score
        status = emp.status
        confidence = explanation.get("confidence", 0)
    else:
        risk_score = explanation["risk_score"]
        status = explanation["status"]
        confidence = explanation.get("confidence", 0)
    role_type = emp.role_type if emp and emp.role_type else explanation.get("role_type", "General")
    role_baseline = explanation.get("role_baseline") or get_role_config(role_type)
    last_triggered_rule = explanation.get("last_triggered_rule") or result.get("risk", {}).get("last_triggered_rule") or "Standard Monitoring"

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
        role_type=role_type,
        role_baseline=role_baseline,
        last_triggered_rule=last_triggered_rule,
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
    department: Optional[str] = None
    role_type: Optional[str] = "General"

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    username: str
    role: str
    name: Optional[str] = None
    role_type: Optional[str] = None
    department: Optional[str] = None

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
    device_name: Optional[str] = None
    vendor_id: Optional[str] = None
    product_id: Optional[str] = None
    serial_number: Optional[str] = None
    drive_letter: Optional[str] = None
    volume_name: Optional[str] = None
    file_system: Optional[str] = None

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
    role_type: str = "General"
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
    role_type: str = "General"
    role_baseline: Optional[dict] = None
    last_triggered_rule: Optional[str] = None
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
    sensitive_files_accessed: List[dict] = []
    top_matched_keywords: List[dict] = []

    class Config:
        from_attributes = True

class RoleUpdateRequest(BaseModel):
    role_type: str

class SensitiveKeywordCreate(BaseModel):
    keyword: str
    category: Optional[str] = "General"
    risk_weight: Optional[int] = 10
    is_active: Optional[bool] = True

class SensitiveKeywordUpdate(BaseModel):
    keyword: Optional[str] = None
    category: Optional[str] = None
    risk_weight: Optional[int] = None
    is_active: Optional[bool] = None

class SensitiveKeywordResponse(BaseModel):
    id: int
    keyword: str
    category: str
    risk_weight: int
    is_active: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

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
    role_type: Optional[str] = "General"
    role_baseline: Optional[dict] = None
    last_triggered_rule: Optional[str] = "Standard Monitoring"
    timestamp: str

class AlertStatusUpdate(BaseModel):
    status: str  # Active | Acknowledged | Investigating | Resolved
    reason: Optional[str] = None

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
    department_risk: List[dict] = []
    most_accessed_sensitive_assets: List[dict] = []

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

    emp = db.query(models.Employee).filter(models.Employee.email == user.username).first()
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "role": user.role,
        "name": _employee_name_for(db, user.username),
        "role_type": emp.role_type if emp else "General",
        "department": emp.department if emp else "General",
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

    role_type = payload.role_type or "General"
    dept = payload.department or (role_type if role_type != "General" else "General")

    # Add to the employee directory so the person is visible/monitorable in SOC.
    emp = db.query(models.Employee).filter(models.Employee.email == username).first()
    if emp is None:
        emp = models.Employee(
            name=payload.name,
            email=username,
            department=dept,
            role_type=role_type,
            risk_score=0,
            status="Normal",
        )
        db.add(emp)
        db.flush()  # get emp.id before creating the DNA row
        profile = db.query(models.BehaviorProfile).filter(models.BehaviorProfile.employee_id == emp.id).first()
        if profile is None:
            db.add(models.BehaviorProfile(
                employee_id=emp.id,
                working_hours_baseline="09:00 - 17:00",
                avg_usb_inserts_per_day=0.0,
                avg_file_copies_per_day=0.0,
                avg_upload_mb_per_day=0.0,
            ))
        else:
            profile.working_hours_baseline = "09:00 - 17:00"
            profile.avg_usb_inserts_per_day = 0.0
            profile.avg_file_copies_per_day = 0.0
            profile.avg_upload_mb_per_day = 0.0
    else:
        if payload.role_type:
            emp.role_type = payload.role_type
        if payload.department:
            emp.department = payload.department

    db.commit()
    db.refresh(user)
    log_action(db, user, "register", "auth", resource_id=str(user.id),
               details=f"Employee account created for '{username}' with role '{role_type}'", ip=ip)

    token, jti, expires_at = create_access_token(user)
    create_session(db, user, jti, expires_at, ip=ip)
    log_action(db, user, "login", "auth", resource_id=str(user.id), details="User login", ip=ip)

    await manager.broadcast({
        "type": "new_login",
        "data": {
            "username": user.username,
            "role": user.role,
            "role_type": role_type,
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
        "role_type": role_type,
        "department": dept,
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

    # Use persisted employee / active-incident scores. Do NOT re-run AI here —
    # that was overwriting Manual Override resets on every dashboard refresh.
    risk_scores = []
    dept_scores = defaultdict(list)

    # Department normalization map
    dept_map = {
        "hr": "Human Resources",
        "human resources": "Human Resources",
        "dev": "Engineering",
        "developer": "Engineering",
        "engineering": "Engineering",
        "eng": "Engineering",
        "finance": "Finance",
        "sales": "Sales",
        "it": "IT Support",
        "it support": "IT Support",
        "marketing": "Marketing",
        "management": "Management",
        "legal": "Legal",
    }

    for emp in employees:
        active_inc = incident_service.get_active_incident(db, emp.id)
        primary = active_inc.risk_score if active_inc else (emp.risk_score or 0)
        risk_scores.append(primary)
        raw_dept = (emp.department or "General").strip()
        dept = dept_map.get(raw_dept.lower(), raw_dept.title())
        role = emp.role_type or "General"
        dept_scores[dept].append((primary, role))

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

    # Department risk distribution
    dept_risk_list = []
    for dept, items in dept_scores.items():
        scores = [s for s, r in items]
        roles = [r for s, r in items]
        top_role = max(set(roles), key=roles.count) if roles else "General"
        avg_dept = round(sum(scores) / len(scores)) if scores else 0
        dept_risk_list.append({
            "department": dept,
            "role": top_role,
            "avg_risk": avg_dept,
            "max_risk": max(scores) if scores else 0,
            "employee_count": len(items)
        })
    dept_risk_list.sort(key=lambda x: x["avg_risk"], reverse=True)

    # Top sensitive assets accessed
    file_evts = db.query(models.Event).filter(
        models.Event.event_type.in_(["file_copy", "file_create", "file_modify", "file_move", "file_rename"])
    ).order_by(models.Event.timestamp.desc()).limit(200).all()
    raw_evts = [{"filename": e.filename, "folder": e.folder, "extension": e.extension, "details": e.details, "event_type": e.event_type} for e in file_evts]
    scan_res = SensitiveAssetScanner.scan_events(raw_evts, db=db)
    top_sensitive = scan_res.get("top_matched_keywords", [])
    if not top_sensitive:
        top_sensitive = [
            {"keyword": "salary", "count": 14},
            {"keyword": "employee", "count": 10},
            {"keyword": "client", "count": 7},
            {"keyword": "budget", "count": 5},
            {"keyword": "source_code", "count": 4},
        ]

    return {
        "total_employees": len(employees),
        "active_alerts": active_alerts,
        "high_risk": high_risk,
        "average_risk": avg_risk,
        "risk_distribution": [{"range": k, "count": v} for k, v in risk_dist.items()],
        "severity_distribution": [{"severity": k, "count": v} for k, v in severity_counts.items()],
        "online_employees": online_counts["online"],
        "offline_employees": online_counts["offline"],
        "department_risk": dept_risk_list,
        "most_accessed_sensitive_assets": top_sensitive,
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
        emp.role_type = emp.role_type or "General"
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
    # Persist live DNA + risk history + correlation alerts so Behavior DNA and
    # Historical Risk Progression stay current for self-registered employees
    # who never got a seeded profile.
    batch_service.persist_risk_and_correlations(db, employee_id, result)
    incident_service.apply_risk(db, employee_id, result)
    db.commit()

    # Reload relationships after persistence so the response reflects the
    # freshly written Behavior DNA and risk history (risk/status may stay at
    # manual 0/Safe when stale-history guard skipped overwrite).
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

    # Role baseline and last triggered rule
    employee.role_type = employee.role_type or "General"
    employee.role_baseline = get_role_config(employee.role_type)
    employee.last_triggered_rule = (
        result.get("explanation", {}).get("last_triggered_rule")
        or result.get("risk", {}).get("last_triggered_rule")
        or "Standard Monitoring"
    )

    # Sensitive files and top matched keywords for employee
    features = result.get("features") or {}
    employee.sensitive_files_accessed = features.get("sensitive_matches") or []
    employee.top_matched_keywords = features.get("top_matched_keywords") or []

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


@router.delete("/employees/{employee_id}")
async def delete_employee(
    employee_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin")),
):
    """Admin endpoint to completely delete an employee, all associated telemetry/alerts/incidents, and release their email and name for demos."""
    emp = db.query(models.Employee).filter(models.Employee.id == employee_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")

    import traceback
    try:
        emp_name = emp.name
        emp_email = emp.email

        # 1. Delete associated Incidents, Events, Alerts, Risk Scores, Profiles, Anomalies, Actions, Commands, Tokens, Devices
        db.query(models.Incident).filter(models.Incident.employee_id == employee_id).delete()
        db.query(models.Event).filter(models.Event.employee_id == employee_id).delete()
        db.query(models.Alert).filter(models.Alert.employee_id == employee_id).delete()
        db.query(models.RiskScore).filter(models.RiskScore.employee_id == employee_id).delete()
        db.query(models.BehaviorProfile).filter(models.BehaviorProfile.employee_id == employee_id).delete()
        db.query(models.UserBehaviorProfile).filter(models.UserBehaviorProfile.employee_id == employee_id).delete()
        db.query(models.BehavioralAnomalyLog).filter(models.BehavioralAnomalyLog.employee_id == employee_id).delete()
        db.query(models.ActionRequest).filter(models.ActionRequest.employee_id == employee_id).delete()
        db.query(models.RemoteCommand).filter(models.RemoteCommand.employee_id == employee_id).delete()
        db.query(models.AgentEnrollmentToken).filter(models.AgentEnrollmentToken.employee_id == employee_id).delete()
        db.query(models.Device).filter(models.Device.employee_id == employee_id).delete()

        # 3. Delete matching User login account and its active sessions so email and username can be reused cleanly
        user_account = db.query(models.User).filter(
            (models.User.username == emp_email) | (models.User.username == emp_name)
        ).first()
        if user_account:
            db.query(models.AuditLog).filter(models.AuditLog.user_id == user_account.id).update({models.AuditLog.user_id: None})
            db.query(models.Session).filter(models.Session.user_id == user_account.id).delete()
            db.delete(user_account)

        # 4. Delete the Employee record itself
        db.delete(emp)
        db.commit()

        # 5. Audit log
        log_action(
            db, current_user, "employee.delete", "employee",
            resource_id=str(employee_id),
            details=f"Completely deleted employee '{emp_name}' ({emp_email}) and released email/credentials",
            ip=client_ip(request),
        )

        # 6. WebSocket broadcast to all connected dashboards and directories
        await manager.broadcast({
            "type": "employee_deleted",
            "data": {
                "employee_id": employee_id,
                "name": emp_name,
                "email": emp_email
            }
        })

        return {
            "success": True,
            "message": f"Employee {emp_name} ({emp_email}) and associated data removed successfully."
        }
    except Exception as e:
        traceback.print_exc()
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete employee: {str(e)}")


# Role Baselines & Employee Role Management
@router.get("/roles/baselines")
def list_role_baselines(
    current_user: models.User = Depends(soc_only),
):
    """List all role baselines, allowable thresholds, and file behaviors."""
    return get_all_role_baselines()


@router.patch("/employees/{employee_id}/role", response_model=EmployeeDetailResponse)
async def update_employee_role(
    employee_id: int,
    payload: RoleUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin", "analyst")),
):
    """Assign or update employee role (e.g. Developer, HR, Finance, Sales)."""
    employee = db.query(models.Employee).filter(models.Employee.id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    old_role = employee.role_type or "General"
    new_role = payload.role_type.strip()
    supported = get_supported_roles()
    matched = next((r for r in supported if r.lower() == new_role.lower()), None)
    if matched:
        new_role = matched
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported role '{new_role}'. Supported: {', '.join(supported)}")

    employee.role_type = new_role
    db.commit()

    # Recompute AI analysis immediately with the new role baseline
    result = _run_ai(db, employee_id)
    batch_service.persist_risk_and_correlations(db, employee_id, result)
    change = incident_service.apply_risk(db, employee_id, result)
    db.commit()
    db.refresh(employee)

    log_action(
        db, current_user, "employee.role_update", "employee",
        resource_id=str(employee_id),
        details=f"Updated role for '{employee.name}' from {old_role} to {new_role}",
        ip=client_ip(request),
    )

    await manager.broadcast({
        "type": "role_updated",
        "data": {
            "employee_id": employee.id,
            "role_type": employee.role_type,
            "risk_score": employee.risk_score,
            "status": employee.status,
        }
    })
    if change:
        await manager.broadcast({"type": change[0], "data": incident_service.serialize(db, change[1])})

    return get_employee_detail(employee_id, db=db, current_user=current_user)


# Sensitive Company Asset Keywords Management (Admin CRUD)
@router.get("/sensitive-keywords", response_model=List[SensitiveKeywordResponse])
def list_sensitive_keywords(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(soc_only),
):
    """List all company-sensitive asset keywords."""
    return db.query(models.SensitiveKeyword).order_by(models.SensitiveKeyword.keyword.asc()).all()


@router.post("/sensitive-keywords", response_model=SensitiveKeywordResponse)
def create_sensitive_keyword(
    payload: SensitiveKeywordCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin")),
):
    """Add a new company-sensitive keyword."""
    kw_str = payload.keyword.strip().lower()
    if not kw_str:
        raise HTTPException(status_code=400, detail="Keyword cannot be empty")
    existing = db.query(models.SensitiveKeyword).filter(models.SensitiveKeyword.keyword == kw_str).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Keyword '{kw_str}' already exists")

    kw = models.SensitiveKeyword(
        keyword=kw_str,
        category=payload.category or "General",
        risk_weight=payload.risk_weight if payload.risk_weight is not None else 10,
        is_active=payload.is_active if payload.is_active is not None else True,
    )
    db.add(kw)
    db.commit()
    db.refresh(kw)
    SensitiveAssetScanner.invalidate_cache()

    log_action(
        db, current_user, "sensitive_keyword.create", "settings",
        resource_id=str(kw.id),
        details=f"Added sensitive keyword '{kw_str}' ({kw.category})",
        ip=client_ip(request),
    )
    return kw


@router.put("/sensitive-keywords/{keyword_id}", response_model=SensitiveKeywordResponse)
def update_sensitive_keyword(
    keyword_id: int,
    payload: SensitiveKeywordUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin")),
):
    """Edit an existing sensitive keyword."""
    kw = db.query(models.SensitiveKeyword).filter(models.SensitiveKeyword.id == keyword_id).first()
    if not kw:
        raise HTTPException(status_code=404, detail="Sensitive keyword not found")

    if payload.keyword is not None:
        new_k = payload.keyword.strip().lower()
        if new_k:
            dup = db.query(models.SensitiveKeyword).filter(models.SensitiveKeyword.keyword == new_k, models.SensitiveKeyword.id != keyword_id).first()
            if dup:
                raise HTTPException(status_code=400, detail=f"Keyword '{new_k}' already exists")
            kw.keyword = new_k
    if payload.category is not None:
        kw.category = payload.category
    if payload.risk_weight is not None:
        kw.risk_weight = payload.risk_weight
    if payload.is_active is not None:
        kw.is_active = payload.is_active

    kw.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(kw)
    SensitiveAssetScanner.invalidate_cache()

    log_action(
        db, current_user, "sensitive_keyword.update", "settings",
        resource_id=str(kw.id),
        details=f"Updated sensitive keyword '{kw.keyword}'",
        ip=client_ip(request),
    )
    return kw


@router.delete("/sensitive-keywords/{keyword_id}")
def delete_sensitive_keyword(
    keyword_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin")),
):
    """Delete a sensitive keyword."""
    kw = db.query(models.SensitiveKeyword).filter(models.SensitiveKeyword.id == keyword_id).first()
    if not kw:
        raise HTTPException(status_code=404, detail="Sensitive keyword not found")

    kw_name = kw.keyword
    db.delete(kw)
    db.commit()
    SensitiveAssetScanner.invalidate_cache()

    log_action(
        db, current_user, "sensitive_keyword.delete", "settings",
        resource_id=str(keyword_id),
        details=f"Deleted sensitive keyword '{kw_name}'",
        ip=client_ip(request),
    )
    return {"message": f"Sensitive keyword '{kw_name}' deleted"}


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


# ---------------------------------------------------------------------------
# Telemetry Event Deduplication / Debouncing Cache (3-second window)
# ---------------------------------------------------------------------------
_EVENT_DEBOUNCE_SECONDS = 3.0
_recent_events_cache = {}  # (employee_id, event_type, key) -> datetime

def _is_duplicate_telemetry(employee_id: int, event_type: str, key_info: str = "") -> bool:
    """True if an identical event occurred within the debounce window."""
    now = datetime.utcnow()
    clean_key = (str(key_info) if key_info else "").strip().lower()
    cache_key = (employee_id, event_type, clean_key)
    last_seen = _recent_events_cache.get(cache_key)
    if last_seen and (now - last_seen).total_seconds() < _EVENT_DEBOUNCE_SECONDS:
        return True
    _recent_events_cache[cache_key] = now
    # Periodic cache cleanup
    if len(_recent_events_cache) > 2000:
        cutoff = now - timedelta(seconds=60)
        for k, v in list(_recent_events_cache.items()):
            if v < cutoff:
                _recent_events_cache.pop(k, None)
    return False


async def broadcast_security_alert(
    alert: Optional[models.Alert],
    event: Optional[models.Event],
    emp: Optional[models.Employee],
    db: Session,
    raw_event_data: Optional[dict] = None
):
    """Broadcast a structured, actionable real-time security alert frame for SOC dashboards."""
    raw = raw_event_data or {}
    if not emp:
        emp_id = (event.employee_id if event else None) or raw.get("employee_id")
        if emp_id:
            emp = db.query(models.Employee).filter(models.Employee.id == emp_id).first()
        if not emp:
            emp = db.query(models.Employee).first()

    dev = get_device(db, emp.id) if emp else None
    dev_dict = device_to_dict(dev) if dev else {}

    event_type = (event.event_type if event else raw.get("event_type", "")) or ""
    if "usb" in event_type:
        alert_category = "usb_connected"
        default_title = "⚠️ USB DEVICE DETECTED"
    elif "process" in event_type:
        alert_category = "suspicious_process"
        default_title = "⚠️ SUSPICIOUS PROCESS DETECTED"
    elif "network" in event_type:
        alert_category = "abnormal_network"
        default_title = "⚠️ ABNORMAL NETWORK SPIKE"
    elif "delete" in event_type:
        alert_category = "evidence_destruction"
        default_title = "⚠️ MASS DELETION DETECTED"
    elif "copy" in event_type or "file_" in event_type:
        alert_category = "mass_file_transfer"
        default_title = "⚠️ MASS FILE ACTIVITY DETECTED"
    else:
        alert_category = "security_anomaly"
        default_title = "⚠️ SECURITY EVENT DETECTED"

    device_name = (
        raw.get("device_name")
        or (event.usb_status if event and event.usb_status else None)
        or "USB Storage Device"
    )
    drive_letter = raw.get("drive_letter") or ""
    vendor_id = raw.get("vendor_id") or "Generic"
    product_id = raw.get("product_id") or "Disk"
    serial_number = raw.get("serial_number") or "N/A"
    volume_name = raw.get("volume_name") or ""
    total_size = raw.get("size") or (event.size if event else "") or ""
    file_system = raw.get("file_system") or ""

    ts_iso = (event.timestamp.isoformat() if event and event.timestamp else datetime.utcnow().isoformat())

    payload = {
        "alert_id": alert.id if alert else None,
        "alert_type": alert_category,
        "title": default_title,
        "employee_id": emp.id if emp else 1,
        "employee_name": emp.name if emp else "Enterprise Employee",
        "department": emp.department if emp else "General",
        "hostname": dev_dict.get("hostname") or "ENDPOINT-PC",
        "device_id": dev_dict.get("device_id") or (f"DEV-{emp.id:04d}" if emp else "DEV-0001"),

        "device_name": device_name,
        "vendor_id": vendor_id,
        "product_id": product_id,
        "serial_number": serial_number,
        "drive_letter": drive_letter,
        "volume_name": volume_name,
        "total_size": total_size,
        "file_system": file_system,
        "severity": alert.severity if alert else "Informational",
        "status": alert.status if alert else "Active",
        "reason": alert.reason if alert else f"Activity detected: {device_name}",
        "details": event.details if event else raw.get("details", ""),
        "timestamp": ts_iso,
    }

    # Broadcast on real-time channel
    await manager.broadcast({"type": "security_alert", "data": payload})


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
    emp_id = event_data.get("employee_id")
    emp = db.query(models.Employee).filter(models.Employee.id == emp_id).first() if emp_id else None
    if not emp:
        emp = db.query(models.Employee).first()
        if not emp:
            raise HTTPException(status_code=400, detail="No registered employees found in system")
        event_data["employee_id"] = emp.id
        emp_id = emp.id

    e_type = event_data.get("event_type", "")
    dedup_key = event_data.get("serial_number") or event_data.get("drive_letter") or event_data.get("filename") or event_data.get("usb_status") or ""

    is_duplicate = _is_duplicate_telemetry(emp_id, e_type, dedup_key)

    created_event = EventService.create_event(db, event_data)

    alerts = []
    if not is_duplicate:
        alerts = RuleBasedAlertEngine.evaluate_event(db, created_event) or []

    db.commit()

    await manager.broadcast({
        "type": "new_event",
        "data": {
            "id": created_event.id,
            "employee_id": created_event.employee_id,
            "event_type": created_event.event_type,
            "filename": created_event.filename,
            "extension": created_event.extension,
            "folder": created_event.folder,
            "size": created_event.size,
            "usb_status": created_event.usb_status,
            "details": created_event.details,
            "timestamp": created_event.timestamp.isoformat(),
        }
    })

    emp = db.query(models.Employee).filter(models.Employee.id == created_event.employee_id).first()

    if alerts:
        for alert in alerts:
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

            # Broadcast rich real-time security alert notification frame
            await broadcast_security_alert(alert, created_event, emp, db, event_data)
    elif created_event.event_type in ("usb_insert", "usb_remove") and not is_duplicate:
        # Broadcast real-time notification frame for USB insert even before AI correlation
        await broadcast_security_alert(None, created_event, emp, db, event_data)

    # Refresh the employee's stored risk + incident state (throttled per employee)
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

    valid_emp_ids = {r[0] for r in db.query(models.Employee.id).all()}
    if not valid_emp_ids:
        return {"ingested": 0, "incidents": 0}
    default_emp_id = next(iter(valid_emp_ids))
    for evt in event_data:
        if evt.get("employee_id") not in valid_emp_ids:
            evt["employee_id"] = default_emp_id

    # Fast path: insert + broadcast immediately (no AI pipeline).
    result = batch_service.process_batch_fast(db, event_data)

    # Broadcast events to all connected dashboards RIGHT NOW.
    await manager.broadcast({"type": "batch_event", "data": result})

    # Broadcast rich security alert popups for any USB insert or critical triggers in batch
    for evt in event_data:
        if evt.get("event_type") == "usb_insert":
            emp = db.query(models.Employee).filter(models.Employee.id == evt.get("employee_id")).first()
            dedup_key = evt.get("serial_number") or evt.get("drive_letter") or evt.get("usb_status") or ""
            if not _is_duplicate_telemetry(evt.get("employee_id", 1), "usb_insert", dedup_key):
                await broadcast_security_alert(None, None, emp, db, evt)

    # Kick off the heavy AI pipeline in a background thread
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
    """Persist alert lifecycle transitions (Active -> Acknowledged -> Investigating -> Resolved)."""
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    valid_statuses = ("Active", "Acknowledged", "Investigating", "Resolved")
    if payload.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"status must be one of {valid_statuses}")

    old_status = alert.status
    alert.status = payload.status
    db.commit()
    db.refresh(alert)

    log_action(
        db, current_user, "alert.update", "alert",
        resource_id=str(alert.id),
        details=f"Alert #{alert.id} status '{old_status}' -> '{alert.status}'" + (f" Reason: {payload.reason}" if payload.reason else ""),
        ip=client_ip(request),
    )

    await _broadcast_alert_update(alert)
    return alert


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertDetailResponse)
async def acknowledge_alert(
    alert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin", "analyst")),
):
    """SOC Analyst/Admin one-click alert acknowledgment."""
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = "Acknowledged"
    db.commit()
    db.refresh(alert)

    log_action(
        db, current_user, "alert.acknowledge", "alert",
        resource_id=str(alert.id),
        details=f"Alert #{alert.id} acknowledged by {current_user.username}",
        ip=client_ip(request),
    )

    await _broadcast_alert_update(alert)
    return alert


@router.post("/alerts/{alert_id}/investigate", response_model=AlertDetailResponse)
async def investigate_alert(
    alert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin", "analyst")),
):
    """Move alert to Investigating status."""
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = "Investigating"
    db.commit()
    db.refresh(alert)

    log_action(
        db, current_user, "alert.investigate", "alert",
        resource_id=str(alert.id),
        details=f"Alert #{alert.id} marked as Investigating by {current_user.username}",
        ip=client_ip(request),
    )

    await _broadcast_alert_update(alert)
    return alert


@router.post("/alerts/{alert_id}/block-usb")
async def block_usb_alert_response(
    alert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin")),
):
    """Admin-only automated response: Issue Block USB command to endpoint and mitigate alert."""
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    emp = alert.employee
    cmd_record = None
    if emp:
        cmd_record = request_command(db, emp.id, "disable_usb", requested_by=current_user.username)

    alert.status = "Investigating"
    db.commit()
    db.refresh(alert)

    log_action(
        db, current_user, "endpoint.block_usb", "device",
        resource_id=str(alert.id),
        details=f"EDR Block USB command issued by {current_user.username} for employee #{alert.employee_id} (Alert #{alert.id})",
        ip=client_ip(request),
    )

    await _broadcast_alert_update(alert)
    return {
        "message": f"USB Storage Disabled on endpoint for {emp.name if emp else 'employee'}",
        "alert_id": alert.id,
        "status": alert.status,
        "command": cmd_record
    }


@router.post("/alerts/{alert_id}/resolve", response_model=AlertDetailResponse)
async def resolve_alert(
    alert_id: int,
    request: Request,
    payload: Optional[IncidentResolveRequest] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin")),
):
    """Admin-only alert resolution."""
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    reason_str = payload.reason if payload else "Resolved by administrator"
    alert.status = "Resolved"
    db.commit()
    db.refresh(alert)

    log_action(
        db, current_user, "alert.resolve", "alert",
        resource_id=str(alert.id),
        details=f"Alert #{alert.id} resolved by {current_user.username}: {reason_str}",
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
            "employee_id": alert.employee_id,
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
    batch_service.persist_risk_and_correlations(db, employee_id, result)
    change = incident_service.apply_risk(db, employee_id, result)
    db.commit()
    db.refresh(employee)

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
    batch_service.persist_risk_and_correlations(db, employee_id, result)
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
    """Admin-only manual override: force an employee back to 0 / Safe. Resolves
    every open incident as Manual Override and writes a fresh resolved anchor so
    AI recomputes cannot snap the score back until new security evidence arrives."""
    employee = db.query(models.Employee).filter(models.Employee.id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    resolved = incident_service.force_manual_override(db, employee_id, current_user.username)
    batch_service.persist_risk_history(db, employee_id, 0)

    log_action(
        db, current_user, "incident.reset_risk", "employee",
        resource_id=str(employee_id),
        details="Reset Risk / Manual Override",
        ip=client_ip(request),
    )
    db.commit()
    db.refresh(employee)

    for inc in resolved:
        await manager.broadcast({
            "type": "incident_resolved",
            "data": incident_service.serialize(db, inc),
        })
    await manager.broadcast({
        "type": "risk_update",
        "data": {str(employee_id): {"score": 0, "status": "Safe", "confidence": 0}},
    })
    return {
        "message": "Employee risk reset",
        "employee": {"id": employee.id, "risk_score": employee.risk_score, "status": employee.status},
        "incident": incident_service.serialize(db, resolved[0]) if resolved else None,
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
    # Prefer an explicitly configured address for LAN deployments. Without it,
    # use the request URL (which is convenient for a single local machine).
    backend_url = PUBLIC_URL or str(request.base_url).rstrip("/")
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
    current_user: models.User = Depends(require_roles("admin", "analyst")),
):
    """List recent commands issued to an employee's endpoint."""
    return list_commands(db, employee_id, limit=20)


# ---------------------------------------------------------------------------
# Action Request (JIT Admin Authorization) Endpoints
# ---------------------------------------------------------------------------
class ActionRequestCreate(BaseModel):
    employee_id: int
    target_file: str
    file_path: str
    action_type: str = "file_delete"
    device_id: Optional[str] = None
    file_size: Optional[str] = None
    risk_context: Optional[str] = None


class ActionRequestResolve(BaseModel):
    notes: Optional[str] = None
    reason: Optional[str] = None


class ActionRequestBatchResolve(BaseModel):
    request_ids: List[int]
    action: str  # "approve" | "reject"
    notes: Optional[str] = None



@router.post("/action-requests")
def create_action_request_endpoint(
    payload: ActionRequestCreate,
    db: Session = Depends(get_db),
):
    """Endpoint for agent to submit an intercepted action request for Admin review."""
    try:
        req = action_request_service.create_action_request(
            db=db,
            employee_id=payload.employee_id,
            target_file=payload.target_file,
            file_path=payload.file_path,
            action_type=payload.action_type,
            device_id=payload.device_id,
            file_size=payload.file_size,
            risk_context=payload.risk_context,
        )
        return req
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/action-requests")
def list_action_requests_endpoint(
    status: Optional[str] = Query(None, description="Filter by status: PENDING, APPROVED, REJECTED"),
    employee_id: Optional[int] = Query(None, description="Filter by employee id"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """List action requests."""
    return action_request_service.list_action_requests(db=db, status=status, employee_id=employee_id, limit=limit)


@router.get("/action-requests/pending-count")
def get_pending_action_requests_count_endpoint(
    db: Session = Depends(get_db),
):
    """Fast count of pending action requests for UI badge."""
    count = action_request_service.get_pending_count(db)
    return {"pending_count": count}


@router.post("/action-requests/{request_id}/approve")
def approve_action_request_endpoint(
    request_id: int,
    payload: Optional[ActionRequestResolve] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin", "analyst")),
):
    """Approve a pending action request."""
    try:
        res = action_request_service.approve_action_request(
            db=db,
            request_id=request_id,
            admin_name=current_user.username if current_user else "Admin",
            notes=payload.notes if payload else None,
        )
        return res
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/action-requests/{request_id}/reject")
def reject_action_request_endpoint(
    request_id: int,
    payload: Optional[ActionRequestResolve] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin", "analyst")),
):
    """Reject a pending action request."""
    try:
        res = action_request_service.reject_action_request(
            db=db,
            request_id=request_id,
            admin_name=current_user.username if current_user else "Admin",
            reason=(payload.reason or payload.notes) if payload else None,
        )
        return res
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/action-requests/batch-resolve")
def batch_resolve_action_requests_endpoint(
    payload: ActionRequestBatchResolve,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin", "analyst")),
):
    """Batch approve or reject multiple action requests in one atomic operation."""
    admin_name = current_user.username if current_user else "Admin"
    results = []
    success_count = 0
    failure_count = 0

    for req_id in payload.request_ids:
        try:
            if payload.action.lower() == "approve":
                res = action_request_service.approve_action_request(
                    db=db,
                    request_id=req_id,
                    admin_name=admin_name,
                    notes=payload.notes or "Batch approved by Administrator",
                )
            else:
                res = action_request_service.reject_action_request(
                    db=db,
                    request_id=req_id,
                    admin_name=admin_name,
                    reason=payload.notes or "Batch denied: security policy violation",
                )
            results.append({"id": req_id, "status": "SUCCESS", "result": res})
            success_count += 1
        except Exception as e:
            results.append({"id": req_id, "status": "FAILED", "error": str(e)})
            failure_count += 1

    return {
        "action": payload.action,
        "total": len(payload.request_ids),
        "success_count": success_count,
        "failure_count": failure_count,
        "results": results,
    }



# --- Priority 2: User Behavior Analytics & Digital Twin Endpoints ------------
@router.get("/users/{user_id}/behavior-profile")
def get_user_behavior_profile_endpoint(
    user_id: int,
    db: Session = Depends(get_db),
):
    """Retrieve or compute rolling 30-day User Behavior Profile for an employee."""
    emp = db.query(models.Employee).filter(models.Employee.id == user_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail=f"Employee #{user_id} not found")
    profile = user_behavior_service.get_or_create_behavior_profile(db, user_id)
    return user_behavior_service.profile_to_dict(profile)


@router.get("/users/{user_id}/digital-twin")
def get_user_digital_twin_endpoint(
    user_id: int,
    db: Session = Depends(get_db),
):
    """Retrieve human-readable Employee Digital Twin behavioral baseline fingerprint."""
    try:
        return digital_twin_service.generate_employee_baseline(db, user_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/users/{user_id}/anomaly-history")
def get_user_anomaly_history_endpoint(
    user_id: int,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """List historical behavioral anomaly detection logs for an employee."""
    import json
    logs = (
        db.query(models.BehavioralAnomalyLog)
        .filter(models.BehavioralAnomalyLog.employee_id == user_id)
        .order_by(models.BehavioralAnomalyLog.detected_at.desc())
        .limit(limit)
        .all()
    )
    result = []
    for l in logs:
        indicators = []
        deviations = {}
        try:
            indicators = json.loads(l.indicators_json)
        except Exception:
            pass
        try:
            deviations = json.loads(l.deviations_json)
        except Exception:
            pass
        result.append({
            "id": l.id,
            "employee_id": l.employee_id,
            "anomaly_score": l.anomaly_score,
            "severity": l.severity,
            "indicators": indicators,
            "deviations": deviations,
            "context": l.context,
            "detected_at": l.detected_at.isoformat() if l.detected_at else None,
        })
    return result


@router.get("/users/{user_id}/risk-history")
def get_user_risk_history_endpoint(
    user_id: int,
    db: Session = Depends(get_db),
):
    """Retrieve historical risk score timeline for an employee."""
    scores = (
        db.query(models.RiskScore)
        .filter(models.RiskScore.employee_id == user_id)
        .order_by(models.RiskScore.recorded_at.desc())
        .limit(30)
        .all()
    )
    return [
        {
            "id": s.id,
            "score": s.score,
            "timestamp": s.recorded_at.isoformat() if s.recorded_at else None,
        }
        for s in scores
    ]


# ===========================================================================
# ThreatVista v2.0: Core SIH High-Impact APIs
# ===========================================================================

# 1. AES-256 Shadow Vault & Key Management
# ---------------------------------------------------------------------------
@router.get("/vault/status")
def get_vault_status_endpoint():
    """Retrieve cryptographic status and AES-256-GCM verification for Shadow Vault."""
    from backend.services.vault_encryption import default_encryption_engine
    return default_encryption_engine.get_vault_security_info()


class KeyRotationRequest(BaseModel):
    new_passphrase: str


@router.post("/vault/rotate-keys")
def rotate_vault_keys_endpoint(
    payload: KeyRotationRequest,
    current_user: models.User = Depends(require_roles("admin")),
):
    """Re-encrypt all shadow vault copies under a new zero-knowledge master key."""
    from backend.services.vault_encryption import default_encryption_engine
    vault_dir = os.path.join(os.path.expanduser("~"), ".threatvista_vault")
    return default_encryption_engine.rotate_vault_keys(payload.new_passphrase, vault_dir)


# 2. Multi-Level Approval Step Endpoint
# ---------------------------------------------------------------------------
class ApprovalStepRequest(BaseModel):
    notes: Optional[str] = None
    approver_name: Optional[str] = "Admin"
    approver_role: Optional[str] = "SOC Admin"


@router.post("/action-requests/{request_id}/approve-step")
def approve_action_step_endpoint(
    request_id: int,
    payload: ApprovalStepRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Advance an action request along its multi-tier approval chain towards quorum."""
    from backend.services.approval_chain_service import process_approval_step
    approver = current_user.username if current_user else (payload.approver_name or "Admin")
    role = current_user.role if current_user else (payload.approver_role or "SOC Admin")
    try:
        return process_approval_step(
            db=db,
            request_id=request_id,
            approver_name=approver,
            approver_role=role,
            notes=payload.notes,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/action-requests/{request_id}/approval-chain")
def get_approval_chain_endpoint(
    request_id: int,
    db: Session = Depends(get_db),
):
    """Retrieve multi-level approval history and quorum progress for a ticket."""
    req = db.query(models.ActionRequest).filter(models.ActionRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Action request not found")
    from backend.services.approval_chain_service import get_approval_chain
    return {
        "request_id": req.id,
        "policy_tier": req.policy_tier or "STANDARD",
        "required_approvals": req.required_approvals or 1,
        "current_approvals": req.current_approvals or 0,
        "status": req.status,
        "chain": get_approval_chain(req),
    }


# 3. Ransomware Mass Rollback & Simulation Demo
# ---------------------------------------------------------------------------
class SimBatchRequest(BaseModel):
    file_count: Optional[int] = 100


@router.post("/recovery/simulate-batch")
def simulate_batch_endpoint(payload: SimBatchRequest):
    """Generate uncorrupted dataset and back up to AES-256 encrypted Shadow Vault."""
    from backend.services.mass_recovery_service import mass_recovery_engine
    return mass_recovery_engine.generate_simulation_batch(payload.file_count or 100)


@router.post("/recovery/simulate-attack")
def simulate_attack_endpoint():
    """Simulate rapid malware attack by encrypting target files with .locked extension."""
    from backend.services.mass_recovery_service import mass_recovery_engine
    return mass_recovery_engine.simulate_ransomware_attack()


@router.post("/recovery/mass-rollback")
def execute_mass_rollback_endpoint(db: Session = Depends(get_db)):
    """Execute 1-Click Mass Rollback restoring all corrupted files from AES-256 Vault."""
    from backend.services.mass_recovery_service import mass_recovery_engine
    return mass_recovery_engine.execute_mass_rollback(db)


@router.get("/recovery/logs")
def get_recovery_logs_endpoint(db: Session = Depends(get_db)):
    """Retrieve mass rollback history logs."""
    logs = db.query(models.RansomwareBatchLog).order_by(models.RansomwareBatchLog.executed_at.desc()).limit(20).all()
    return [
        {
            "id": l.id,
            "batch_size": l.batch_size,
            "recovered_count": l.recovered_count,
            "failed_count": l.failed_count,
            "data_volume_mb": l.data_volume_mb,
            "recovery_time_ms": l.recovery_time_ms,
            "status": l.status,
            "initiated_by": l.initiated_by,
            "executed_at": l.executed_at.isoformat() if l.executed_at else None,
        }
        for l in logs
    ]


# 4. ThreatVista AI Security Copilot & NL Investigation
# ---------------------------------------------------------------------------
class CopilotChatRequest(BaseModel):
    message: str
    employee_id: Optional[int] = None
    context: Optional[dict] = None


@router.post("/copilot/explain-risk")
def explain_risk_endpoint(
    employee_id: int = Query(..., description="ID of employee to explain"),
    db: Session = Depends(get_db),
):
    """Generate explainable AI risk breakdown and MITRE ATT&CK mapping for an employee."""
    from backend.services.threat_copilot import explain_employee_risk
    return explain_employee_risk(db, employee_id)


@router.post("/copilot/chat")
def copilot_chat_endpoint(
    payload: CopilotChatRequest,
    db: Session = Depends(get_db),
):
    """Conversational security copilot for SOC analysts."""
    from backend.services.threat_copilot import copilot_chat
    return copilot_chat(db, payload.message, payload.employee_id, payload.context)


class NLInvestigateRequest(BaseModel):
    query: str


@router.post("/copilot/investigate")
def nl_investigate_endpoint(
    payload: NLInvestigateRequest,
    db: Session = Depends(get_db),
):
    """Translate natural language questions into structured database searches."""
    from backend.services.nl_query_service import execute_natural_language_investigation
    return execute_natural_language_investigation(db, payload.query)


class DocumentClassifyRequest(BaseModel):
    content: str
    filename: Optional[str] = "document.txt"


@router.post("/ai/classify-document")
def classify_document_endpoint(payload: DocumentClassifyRequest):
    """Deep document inspection for PII, credentials, financial records, and legal markings."""
    from backend.services.llm_classifier import inspect_document_content
    return inspect_document_content(payload.content, payload.filename)


# 5. Threat Timeline Visualization Data
# ---------------------------------------------------------------------------
@router.get("/users/{user_id}/threat-timeline")
def get_user_threat_timeline_endpoint(
    user_id: int,
    db: Session = Depends(get_db),
):
    """Generate unified chronological timeline of telemetry, vault restorations, approvals, and alerts."""
    emp = db.query(models.Employee).filter(models.Employee.id == user_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")

    timeline_items = []
    sensitive_keywords = ["salary", "employee", "client", "budget", "source_code", "contract", "password", "secret", "financial", "dump", "database", "ssn", "credit"]

    # 1. Telemetry events (up to 100)
    events = db.query(models.Event).filter(models.Event.employee_id == user_id).order_by(models.Event.timestamp.desc()).limit(100).all()
    for ev in events:
        category = "FILE"
        severity = "LOW"
        icon = "file"
        ev_type = (ev.event_type or "").lower()
        title = f"{ev.event_type.replace('_', ' ').title() if ev.event_type else 'File Activity'}"
        
        fname = (ev.filename or "").lower()
        details = (ev.details or "").lower()
        is_sensitive = any(k in fname or k in details for k in sensitive_keywords)

        if "usb" in ev_type or ev.usb_status in ("inserted", "blocked", "quarantined"):
            category = "USB"
            severity = "HIGH"
            icon = "usb"
            title = f"USB Removable Storage Operation: {ev.filename or 'Device Event'}"
        elif "delete" in ev_type:
            category = "VAULT"
            severity = "HIGH"
            icon = "shield"
            title = f"File Deletion Intercepted & Restored: {ev.filename or 'Protected Asset'}"
        elif "network" in ev_type:
            category = "NETWORK"
            severity = "MEDIUM" if not is_sensitive else "HIGH"
            icon = "network"
            title = f"Network Data Transfer ({ev.network_upload or 'Active Transfer'})"
        elif "process" in ev_type:
            category = "PROCESS"
            severity = "MEDIUM"
            icon = "cpu"
            title = f"Process Execution: {ev.filename or 'System Binary'}"
        elif "login" in ev_type:
            category = "AUTH"
            severity = "LOW"
            icon = "key"
            title = "User Authenticated to Workstation"
        elif is_sensitive:
            category = "SENSITIVE"
            severity = "HIGH"
            icon = "file-text"
            title = f"Sensitive Asset Accessed: {ev.filename or 'Confidential Record'}"

        timeline_items.append({
            "id": f"event_{ev.id}",
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else datetime.utcnow().isoformat(),
            "category": category,
            "severity": severity,
            "icon": icon,
            "title": title,
            "detail": ev.details or f"File: {ev.filename} ({ev.size or 'N/A'}) | Path: {ev.folder or 'Local Workstation'}",
            "raw_type": ev.event_type,
            "filename": ev.filename,
            "folder": ev.folder,
            "size": ev.size,
            "network_upload": ev.network_upload,
            "usb_status": ev.usb_status,
            "is_sensitive": is_sensitive,
        })

    # 2. JIT Action Requests & Approvals (Full Lifecycle: Approved, Rejected, Pending, Quorum)
    requests = db.query(models.ActionRequest).filter(models.ActionRequest.employee_id == user_id).order_by(models.ActionRequest.requested_at.desc()).limit(50).all()
    for req in requests:
        action_title = "File Deletion" if req.action_type == "file_delete" else ("USB Exfiltration" if req.action_type == "usb_export" else "Privileged Action")
        status_label = req.status.upper()
        
        if status_label in ("APPROVED", "PARTIALLY_APPROVED"):
            status_desc = f"✅ APPROVED by {req.resolved_by or 'Security Admin'}"
            if req.resolution_notes:
                status_desc += f" (Note: {req.resolution_notes})"
            severity = "LOW"
        elif status_label == "REJECTED":
            status_desc = f"❌ REJECTED / BLOCKED by {req.resolved_by or 'Security Team'}"
            if req.resolution_notes:
                status_desc += f" (Reason: {req.resolution_notes})"
            severity = "CRITICAL"
        else:
            status_desc = f"⏳ PENDING REVIEW (Quorum: {req.current_approvals or 0}/{req.required_approvals or 1} Approvals)"
            severity = "HIGH"

        timeline_items.append({
            "id": f"req_{req.id}",
            "timestamp": (req.resolved_at or req.requested_at or datetime.utcnow()).isoformat(),
            "category": "APPROVAL",
            "severity": severity,
            "icon": "user-check" if status_label == "APPROVED" else ("shield-alert" if status_label == "REJECTED" else "alert"),
            "title": f"JIT Action Approval Ticket #{req.id}: {action_title} — [{status_label}]",
            "detail": f"Target: {req.target_file} | Classification: {req.file_classification} (Tier: {req.policy_tier}) | Result: {status_desc} | Risk: {req.calculated_risk_score}%",
            "raw_type": "jit_request",
            "approval_status": status_label,
            "resolved_by": req.resolved_by,
            "resolution_notes": req.resolution_notes,
            "policy_tier": req.policy_tier,
            "file_classification": req.file_classification,
            "current_approvals": req.current_approvals or 0,
            "required_approvals": req.required_approvals or 1,
            "target_file": req.target_file,
            "file_path": req.file_path,
        })

    # 3. Security Alerts & Threat Correlations
    alerts = db.query(models.Alert).filter(models.Alert.employee_id == user_id).order_by(models.Alert.timestamp.desc()).limit(40).all()
    for al in alerts:
        timeline_items.append({
            "id": f"alert_{al.id}",
            "timestamp": al.timestamp.isoformat() if al.timestamp else datetime.utcnow().isoformat(),
            "category": "ALERT",
            "severity": "CRITICAL" if al.severity in ("Critical", "High") else "HIGH",
            "icon": "shield-alert",
            "title": f"Security Detection Trigger: {al.reason[:70]}",
            "detail": f"Rule: {al.reason} | Severity: {al.severity} | Status: {al.status}",
            "raw_type": "security_alert",
        })

    # Sort all items descending by timestamp
    timeline_items.sort(key=lambda x: x["timestamp"], reverse=True)

    return {
        "employee_id": emp.id,
        "employee_name": emp.name,
        "department": emp.department,
        "total_items": len(timeline_items),
        "timeline": timeline_items,
    }



