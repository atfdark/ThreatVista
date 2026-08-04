from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from backend.database.connection import get_db
from backend.models import database as models
from backend.services.event_service import EventService
from backend.services.alert_engine import RuleBasedAlertEngine
from backend.services.config_service import get_config, get_thresholds, to_dict, update_config
from backend.websocket.manager import manager
from backend.auth import create_access_token, get_current_user, hash_password, verify_password, require_roles
from ai.pipeline import AIPipeline

router = APIRouter()

ai_pipeline = AIPipeline()


def _run_ai(db: Session, employee_id: int):
    """Run the AI pipeline for an employee, applying persisted risk thresholds."""
    events = db.query(models.Event).filter(models.Event.employee_id == employee_id).all()
    raw = [{"id": e.id, "event_type": e.event_type, "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "size": e.size, "extension": e.extension, "folder": e.folder, "usb_status": e.usb_status,
            "network_upload": e.network_upload, "cpu_usage": e.cpu_usage, "ram_usage": e.ram_usage,
            "details": e.details} for e in events]
    thresholds = get_thresholds(db)
    return ai_pipeline.run(raw, employee_id, thresholds)

# Pydantic Schemas
class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    username: str
    role: str

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

class EmployeeBase(BaseModel):
    id: int
    name: str
    email: str
    department: str
    photo_url: Optional[str]
    risk_score: int
    status: str

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
    timestamp: str

class DashboardResponse(BaseModel):
    total_employees: int
    active_alerts: int
    high_risk: int
    average_risk: float
    risk_distribution: List[dict]
    severity_distribution: List[dict]


# Auth Login Endpoint
@router.post("/auth/login", response_model=TokenResponse)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == request.username).first()
    if not user or not verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    token = create_access_token(user)
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "role": user.role
    }

@router.post("/auth/logout")
def logout(current_user: models.User = Depends(get_current_user)):
    return {"message": f"{current_user.username} logged out successfully"}

@router.get("/auth/me")
def get_me(current_user: models.User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role
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
    current_user: models.User = Depends(get_current_user),
):
    employees = db.query(models.Employee).all()
    alerts = db.query(models.Alert).all()

    risk_scores = []
    for emp in employees:
        result = _run_ai(db, emp.id)
        explanation = result["explanation"]
        emp.risk_score = int(explanation["risk_score"])
        emp.status = explanation["status"]
        risk_scores.append(explanation["risk_score"])
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

    return {
        "total_employees": len(employees),
        "active_alerts": active_alerts,
        "high_risk": high_risk,
        "average_risk": avg_risk,
        "risk_distribution": [{"range": k, "count": v} for k, v in risk_dist.items()],
        "severity_distribution": [{"severity": k, "count": v} for k, v in severity_counts.items()]
    }


# Employees
@router.get("/employees", response_model=List[EmployeeBase])
def get_employees(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    employees = db.query(models.Employee).all()
    return employees

@router.get("/employees/{employee_id}", response_model=EmployeeDetailResponse)
def get_employee_detail(
    employee_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    employee = db.query(models.Employee).filter(models.Employee.id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    employee.events = sorted(employee.events, key=lambda x: x.timestamp, reverse=True)
    employee.risk_scores = sorted(employee.risk_scores, key=lambda x: x.recorded_at)

    result = _run_ai(db, employee_id)
    explanation = result["explanation"]
    employee.ai_analysis = AIAnalysisResponse(
        employee_id=employee_id,
        risk_score=explanation["risk_score"],
        status=explanation["status"],
        reasons=explanation["reasons"],
        recommendations=explanation["recommendations"],
        deviation=explanation.get("deviation", {}),
        model_anomaly=explanation.get("model_anomaly", False),
        model_score=explanation.get("model_score", 0),
        timestamp=result["timestamp"]
    )

    return employee


# Events
@router.post("/events", response_model=EventResponse)
async def create_event(event: EventCreate, db: Session = Depends(get_db)):
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
            await manager.broadcast({
                "type": "new_alert",
                "data": {
                    "id": alert.id,
                    "severity": alert.severity,
                    "reason": alert.reason,
                    "status": alert.status,
                    "timestamp": alert.timestamp.isoformat()
                }
            })

    return created_event

@router.get("/events", response_model=List[EventResponse])
def get_events(
    skip: int = 0,
    limit: int = 100,
    employee_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
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
    current_user: models.User = Depends(get_current_user),
):
    alerts = db.query(models.Alert).all()
    alerts = sorted(alerts, key=lambda x: x.timestamp, reverse=True)
    return alerts


# AI Analysis
@router.post("/ai/analyze/{employee_id}", response_model=AIAnalysisResponse)
def analyze_employee(
    employee_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    employee = db.query(models.Employee).filter(models.Employee.id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    result = _run_ai(db, employee_id)
    explanation = result["explanation"]

    employee.risk_score = int(explanation["risk_score"])
    employee.status = explanation["status"]
    db.commit()

    return AIAnalysisResponse(
        employee_id=employee_id,
        risk_score=explanation["risk_score"],
        status=explanation["status"],
        reasons=explanation["reasons"],
        recommendations=explanation["recommendations"],
        deviation=explanation.get("deviation", {}),
        model_anomaly=explanation.get("model_anomaly", False),
        model_score=explanation.get("model_score", 0),
        timestamp=result["timestamp"]
    )

@router.get("/ai/analysis/{employee_id}", response_model=AIAnalysisResponse)
def get_ai_analysis(
    employee_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    employee = db.query(models.Employee).filter(models.Employee.id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    result = _run_ai(db, employee_id)
    explanation = result["explanation"]

    return AIAnalysisResponse(
        employee_id=employee_id,
        risk_score=explanation["risk_score"],
        status=explanation["status"],
        reasons=explanation["reasons"],
        recommendations=explanation["recommendations"],
        deviation=explanation.get("deviation", {}),
        model_anomaly=explanation.get("model_anomaly", False),
        model_score=explanation.get("model_score", 0),
        timestamp=result["timestamp"]
    )


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
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("admin", "analyst")),
):
    updated = update_config(db, payload)
    return to_dict(updated)
