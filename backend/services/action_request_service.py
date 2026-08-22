"""
ThreatVista JIT Action Authorization & Request Service.

Handles lifecycle of intercepted endpoint actions (e.g. file deletions, USB exports):
- Runs AI File Sensitivity Classification (RESTRICTED, CONFIDENTIAL, INTERNAL, PUBLIC).
- Computes Explainable Dynamic Risk Scoring (0-100, LOW/MEDIUM/HIGH, and human-readable factor trail).
- Enforces 5-minute request TTL with automatic expiration.
- Endpoint agent submits PENDING ActionRequest.
- Service stores ticket in database and broadcasts real-time WebSocket event to all Admins.
- Admin approves -> Ticket marked APPROVED, execution command dispatched to endpoint agent.
- Admin rejects -> Ticket marked REJECTED, security alert logged, risk penalty applied.
"""
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from backend.models.database import ActionRequest, Employee, Alert
from backend.websocket.manager import manager
from backend.services.file_classifier import classify_file
from backend.services.jit_risk_engine import calculate_risk_score

EXPIRY_MINUTES = 5


def action_request_to_dict(req: ActionRequest) -> Dict:
    """Format ActionRequest instance into API/WebSocket response payload."""
    emp = req.employee
    
    # Parse risk explanations JSON safely
    explanation = []
    if req.risk_explanation_json:
        try:
            explanation = json.loads(req.risk_explanation_json)
        except Exception:
            explanation = [req.risk_explanation_json]

    # Check expiration dynamically
    now = datetime.utcnow()
    is_expired = False
    if req.status == "PENDING" and req.expires_at and now > req.expires_at:
        is_expired = True

    return {
        "id": req.id,
        "employee_id": req.employee_id,
        "employee_name": emp.name if emp else "Unknown",
        "employee_role": emp.role_type if emp else "General",
        "employee_department": emp.department if emp else "General",
        "employee_risk_score": emp.risk_score if emp else 0,
        "employee_status": emp.status if emp else "Normal",
        "device_id": req.device_id,
        "action_type": req.action_type,
        "target_file": req.target_file,
        "file_path": req.file_path,
        "file_size": req.file_size,
        "status": "EXPIRED" if is_expired else req.status,
        "risk_context": req.risk_context,
        
        # Priority 1: AI File Sensitivity Classification
        "file_classification": req.file_classification or "INTERNAL",
        "classification_confidence": round(req.classification_confidence or 0.85, 2),
        "classification_reason": req.classification_reason or "Automated classification",
        
        # Priority 1: Explainable Risk Scoring Engine
        "calculated_risk_score": req.calculated_risk_score or 0,
        "calculated_risk_level": req.calculated_risk_level or "LOW",
        "risk_explanation": explanation,
        
        # Priority 1: Automatic Request Expiration
        "requested_at": req.requested_at.isoformat() if req.requested_at else None,
        "expires_at": req.expires_at.isoformat() if req.expires_at else None,
        "is_expired": is_expired,
        "resolved_at": req.resolved_at.isoformat() if req.resolved_at else None,
        "resolved_by": req.resolved_by,
        "resolution_notes": req.resolution_notes,
    }


def create_action_request(
    db: Session,
    employee_id: int,
    target_file: str,
    file_path: str,
    action_type: str = "file_delete",
    device_id: Optional[str] = None,
    file_size: Optional[str] = None,
    risk_context: Optional[str] = None,
) -> Dict:
    """Record an intercepted action, classify file sensitivity, compute explainable risk, and alert SOC."""
    emp = db.query(Employee).filter(Employee.id == employee_id).first()
    if not emp:
        raise ValueError(f"Employee {employee_id} not found")

    now = datetime.utcnow()
    expires_at = now + timedelta(minutes=EXPIRY_MINUTES)

    # Deduplication check: Do not create duplicate pending requests for the same action/file
    existing_req = (
        db.query(ActionRequest)
        .filter(
            ActionRequest.employee_id == employee_id,
            ActionRequest.action_type == action_type,
            ActionRequest.status == "PENDING",
            (ActionRequest.expires_at == None) | (ActionRequest.expires_at > now),
            (ActionRequest.file_path == file_path) | (ActionRequest.target_file == target_file),
        )
        .first()
    )

    if existing_req:
        if file_size and not existing_req.file_size:
            existing_req.file_size = file_size
            db.commit()
            db.refresh(existing_req)
        return action_request_to_dict(existing_req)

    # 1. AI File Sensitivity Classification
    cls_res = classify_file(file_path=file_path, filename=target_file)
    classification = cls_res.get("classification", "INTERNAL")
    confidence = cls_res.get("confidence", 0.85)
    cls_reason = cls_res.get("reason", "")

    # 2. Explainable Dynamic Risk Scoring Engine
    risk_res = calculate_risk_score(
        db=db,
        employee_id=employee_id,
        action_type=action_type,
        file_path=file_path,
        classification=classification,
        target_time=now,
    )
    risk_score = risk_res.get("risk_score", 0)
    risk_level = risk_res.get("risk_level", "LOW")
    explanation_list = risk_res.get("explanation", [])

    # If risk context not provided, generate smart summary based on classification and action
    if not risk_context:
        risk_context = (
            f"Intercepted {action_type.replace('_', ' ').upper()} on {classification} file '{target_file}' "
            f"by {emp.name} ({emp.role_type}). Risk Score: {risk_score}% ({risk_level})."
        )

    req = ActionRequest(
        employee_id=employee_id,
        device_id=device_id,
        action_type=action_type,
        target_file=target_file,
        file_path=file_path,
        file_size=file_size,
        status="PENDING",
        risk_context=risk_context,
        file_classification=classification,
        classification_confidence=confidence,
        classification_reason=cls_reason,
        calculated_risk_score=risk_score,
        calculated_risk_level=risk_level,
        risk_explanation_json=json.dumps(explanation_list),
        requested_at=now,
        expires_at=expires_at,
    )
    db.add(req)
    db.commit()
    db.refresh(req)

    data = action_request_to_dict(req)

    # Real-time WebSocket broadcast to all connected SOC dashboards
    manager.broadcast_nowait({
        "type": "action_request_created",
        "action_request": data,
        "pending_count": get_pending_count(db),
    })

    return data


def list_action_requests(
    db: Session,
    status: Optional[str] = None,
    employee_id: Optional[int] = None,
    limit: int = 50,
) -> List[Dict]:
    """Retrieve action approval tickets with optional status filtering."""
    query = db.query(ActionRequest)
    if status:
        if status.upper() == "PENDING":
            now = datetime.utcnow()
            # Only genuinely pending (not expired)
            query = query.filter(
                ActionRequest.status == "PENDING",
                (ActionRequest.expires_at == None) | (ActionRequest.expires_at > now),
            )
        elif status.upper() == "EXPIRED":
            now = datetime.utcnow()
            query = query.filter(
                (ActionRequest.status == "EXPIRED") |
                ((ActionRequest.status == "PENDING") & (ActionRequest.expires_at <= now))
            )
        else:
            query = query.filter(ActionRequest.status == status.upper())

    if employee_id:
        query = query.filter(ActionRequest.employee_id == employee_id)

    records = query.order_by(ActionRequest.requested_at.desc()).limit(limit).all()
    return [action_request_to_dict(r) for r in records]


def get_pending_count(db: Session) -> int:
    """Return total number of active pending action requests (excluding expired)."""
    now = datetime.utcnow()
    return db.query(ActionRequest).filter(
        ActionRequest.status == "PENDING",
        (ActionRequest.expires_at == None) | (ActionRequest.expires_at > now),
    ).count()


def approve_action_request(
    db: Session,
    request_id: int,
    admin_name: str = "Admin",
    notes: Optional[str] = None,
) -> Dict:
    """Approve the pending action and dispatch execute command to endpoint agent."""
    req = db.query(ActionRequest).filter(ActionRequest.id == request_id).first()
    if not req:
        raise ValueError(f"Action request #{request_id} not found")

    now = datetime.utcnow()
    if req.status == "EXPIRED" or (req.status == "PENDING" and req.expires_at and now > req.expires_at):
        req.status = "EXPIRED"
        db.commit()
        raise ValueError(f"Action request #{request_id} has expired (5-minute TTL exceeded)")

    if req.status != "PENDING":
        raise ValueError(f"Action request #{request_id} is already {req.status}")

    req.status = "APPROVED"
    req.resolved_at = now
    req.resolved_by = admin_name
    req.resolution_notes = notes or "Action approved by Security Administrator"

    # Batch-resolve any sibling pending duplicates for the same employee & file
    duplicates = db.query(ActionRequest).filter(
        ActionRequest.employee_id == req.employee_id,
        ActionRequest.target_file == req.target_file,
        ActionRequest.action_type == req.action_type,
        ActionRequest.status == "PENDING",
        ActionRequest.id != req.id,
    ).all()
    for dup in duplicates:
        dup.status = "APPROVED"
        dup.resolved_at = now
        dup.resolved_by = admin_name
        dup.resolution_notes = f"Batch-approved with ticket #{req.id}"

    db.commit()
    db.refresh(req)

    data = action_request_to_dict(req)

    # Broadcast resolution to dashboards and endpoint agents
    manager.broadcast_nowait({
        "type": "action_request_resolved",
        "action_request": data,
        "command": "EXECUTE_ACTION",
        "pending_count": get_pending_count(db),
    })

    return data


def reject_action_request(
    db: Session,
    request_id: int,
    admin_name: str = "Admin",
    reason: Optional[str] = None,
) -> Dict:
    """Reject the action request, maintain protection, and log security alert."""
    req = db.query(ActionRequest).filter(ActionRequest.id == request_id).first()
    if not req:
        raise ValueError(f"Action request #{request_id} not found")

    now = datetime.utcnow()
    if req.status == "EXPIRED" or (req.status == "PENDING" and req.expires_at and now > req.expires_at):
        req.status = "EXPIRED"
        db.commit()
        raise ValueError(f"Action request #{request_id} has expired (5-minute TTL exceeded)")

    if req.status != "PENDING":
        raise ValueError(f"Action request #{request_id} is already {req.status}")

    req.status = "REJECTED"
    req.resolved_at = now
    req.resolved_by = admin_name
    req.resolution_notes = reason or "Action denied: security policy violation"

    # Batch-resolve any sibling pending duplicates for the same employee & file
    duplicates = db.query(ActionRequest).filter(
        ActionRequest.employee_id == req.employee_id,
        ActionRequest.target_file == req.target_file,
        ActionRequest.action_type == req.action_type,
        ActionRequest.status == "PENDING",
        ActionRequest.id != req.id,
    ).all()
    for dup in duplicates:
        dup.status = "REJECTED"
        dup.resolved_at = now
        dup.resolved_by = admin_name
        dup.resolution_notes = f"Batch-rejected with ticket #{req.id}"

    # Create security alert for employee
    alert = Alert(
        employee_id=req.employee_id,
        severity="High",
        reason=f"Unauthorized {req.action_type.replace('_', ' ')} on {req.file_classification} '{req.target_file}' was BLOCKED by Admin ({admin_name}).",
        status="Active",
        timestamp=now,
    )
    db.add(alert)

    # Elevate employee risk score slightly due to rejected violation (+10)
    emp = req.employee
    if emp:
        emp.risk_score = min(100, (emp.risk_score or 0) + 10)
        if emp.risk_score >= 75:
            emp.status = "High Risk"
        elif emp.risk_score >= 50:
            emp.status = "Suspicious"

    db.commit()
    db.refresh(req)

    data = action_request_to_dict(req)

    # Broadcast resolution
    manager.broadcast_nowait({
        "type": "action_request_resolved",
        "action_request": data,
        "command": "MAINTAIN_BLOCK",
        "pending_count": get_pending_count(db),
    })

    return data

