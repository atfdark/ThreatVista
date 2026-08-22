"""
ThreatVista Multi-Level Approval Chain Service.

Implements enterprise multi-tier quorum policies for high-risk and restricted operations:
- PUBLIC Assets: 0 Approvals (Auto-Approved)
- INTERNAL Assets: 1 Approval (Standard SOC Analyst / Admin)
- CONFIDENTIAL Assets: 1 Approval (Elevated SOC Lead / Manager)
- RESTRICTED Assets: 2 Approvals (Dual Quorum: SOC Admin + Compliance Officer / Department Head)

Provides full forensic trail of approval steps, partial quorum states, and automatic agent dispatching.
"""
import json
from datetime import datetime
from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from backend.models.database import ActionRequest, Employee, Alert
from backend.websocket.manager import manager
from backend.services.command_service import request_command

POLICY_AUTO = "AUTO"
POLICY_STANDARD = "STANDARD"
POLICY_ELEVATED = "ELEVATED"
POLICY_DUAL_QUORUM = "DUAL_QUORUM"


def determine_approval_policy(classification: str, risk_score: int = 0) -> Dict:
    """Determine the required number of approvals and policy tier based on sensitivity and risk."""
    cls_upper = (classification or "INTERNAL").upper()

    if cls_upper == "PUBLIC":
        return {
            "required_approvals": 0,
            "policy_tier": POLICY_AUTO,
            "required_roles": [],
            "description": "Public low-risk asset (Zero approval / Auto-dispatch)",
        }
    elif cls_upper == "RESTRICTED":
        return {
            "required_approvals": 2,
            "policy_tier": POLICY_DUAL_QUORUM,
            "required_roles": ["SOC Lead / Security Admin", "Compliance Officer / Department Head"],
            "description": "Restricted tier asset (Dual-Quorum: 2 independent authorizers required)",
        }
    elif cls_upper == "CONFIDENTIAL":
        return {
            "required_approvals": 1,
            "policy_tier": POLICY_ELEVATED,
            "required_roles": ["SOC Lead or Department Manager"],
            "description": "Confidential asset (Elevated single-tier review)",
        }
    else:  # INTERNAL
        return {
            "required_approvals": 1,
            "policy_tier": POLICY_STANDARD,
            "required_roles": ["Security Analyst or Admin"],
            "description": "Internal business asset (Standard single review)",
        }



def get_approval_chain(req: ActionRequest) -> List[Dict]:
    """Parse the stored approval chain JSON array safely."""
    try:
        data = json.loads(req.approval_chain_json or "[]")
        return data if isinstance(data, list) else []
    except Exception:
        return []


def process_approval_step(
    db: Session,
    request_id: int,
    approver_name: str = "Admin",
    approver_role: str = "SOC Admin",
    notes: Optional[str] = None,
) -> Dict:
    """Record an approval step for a pending action request, advancing towards quorum."""
    req = db.query(ActionRequest).filter(ActionRequest.id == request_id).first()
    if not req:
        raise ValueError(f"Action request #{request_id} not found")

    now = datetime.utcnow()
    if req.status == "EXPIRED" or (req.status in {"PENDING", "PARTIALLY_APPROVED"} and req.expires_at and now > req.expires_at):
        req.status = "EXPIRED"
        db.commit()
        raise ValueError(f"Action request #{request_id} has expired (5-minute TTL exceeded)")

    if req.status in {"APPROVED", "REJECTED"}:
        raise ValueError(f"Action request #{request_id} is already in terminal state: {req.status}")

    # Check for duplicate approval from the same approver
    chain = get_approval_chain(req)
    if any(step.get("approver_name") == approver_name for step in chain):
        # Allow only if single approval policy, else reject duplicate vote
        if req.required_approvals > 1:
            raise ValueError(f"Approver '{approver_name}' has already cast an approval for ticket #{request_id}. A different authorizer is required.")

    # Record approval step
    step_record = {
        "step": len(chain) + 1,
        "approver_name": approver_name,
        "approver_role": approver_role,
        "decision": "APPROVED",
        "timestamp": now.isoformat(),
        "notes": notes or f"Approved by {approver_name} ({approver_role})",
    }
    chain.append(step_record)
    req.approval_chain_json = json.dumps(chain)
    req.current_approvals = (req.current_approvals or 0) + 1

    # Check if quorum is met
    if req.current_approvals >= req.required_approvals:
        req.status = "APPROVED"
        req.resolved_at = now
        req.resolved_by = approver_name
        req.resolution_notes = notes or f"Quorum met ({req.current_approvals}/{req.required_approvals}). Action authorized."

        # Dispatch execution command to endpoint agent
        if req.action_type in {"file_delete", "usb_export", "script_execution"}:
            cmd_details = json.dumps({
                "action_request_id": req.id,
                "action_type": req.action_type,
                "target_file": req.target_file,
                "file_path": req.file_path,
                "authorized_by": approver_name,
                "multi_approval_quorum": f"{req.current_approvals}/{req.required_approvals}",
            })
            request_command(
                db=db,
                employee_id=req.employee_id,
                command="execute_approved_action",
                requested_by=approver_name,
                details=cmd_details,
            )
    else:
        req.status = "PARTIALLY_APPROVED"
        req.resolution_notes = f"Step {req.current_approvals}/{req.required_approvals} completed by {approver_name}. Waiting for second authorizer."

    db.commit()
    db.refresh(req)

    # Broadcast real-time WebSocket update
    from backend.services.action_request_service import action_request_to_dict, get_pending_count
    data = action_request_to_dict(req)
    manager.broadcast_nowait({
        "type": "action_request_updated",
        "action_request": data,
        "pending_count": get_pending_count(db),
    })

    return data


def reject_approval_step(
    db: Session,
    request_id: int,
    rejecter_name: str = "Admin",
    rejecter_role: str = "SOC Admin",
    reason: Optional[str] = None,
) -> Dict:
    """Reject an action request at any stage of the approval chain."""
    req = db.query(ActionRequest).filter(ActionRequest.id == request_id).first()
    if not req:
        raise ValueError(f"Action request #{request_id} not found")

    now = datetime.utcnow()
    chain = get_approval_chain(req)
    step_record = {
        "step": len(chain) + 1,
        "approver_name": rejecter_name,
        "approver_role": rejecter_role,
        "decision": "REJECTED",
        "timestamp": now.isoformat(),
        "notes": reason or f"Denied by {rejecter_name} ({rejecter_role})",
    }
    chain.append(step_record)
    req.approval_chain_json = json.dumps(chain)
    req.status = "REJECTED"
    req.resolved_at = now
    req.resolved_by = rejecter_name
    req.resolution_notes = reason or f"Action denied by {rejecter_name} ({rejecter_role})"

    # Log security alert
    alert = Alert(
        employee_id=req.employee_id,
        severity="High",
        reason=f"JIT Action Denied: Attempted {req.action_type.replace('_', ' ')} on {req.file_classification} file '{req.target_file}'. Reason: {req.resolution_notes}",
        status="Active",
        timestamp=now,
    )
    db.add(alert)

    # Adjust employee risk
    emp = req.employee
    if emp:
        emp.risk_score = min(100, (emp.risk_score or 0) + 15)
        if emp.risk_score >= 75:
            emp.status = "High Risk"
        elif emp.risk_score >= 50:
            emp.status = "Suspicious"

    db.commit()
    db.refresh(req)

    from backend.services.action_request_service import action_request_to_dict, get_pending_count
    data = action_request_to_dict(req)
    manager.broadcast_nowait({
        "type": "action_request_updated",
        "action_request": data,
        "pending_count": get_pending_count(db),
    })

    return data
