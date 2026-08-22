"""
ThreatVista Natural Language Security Investigation Engine.

Translates plain-English analyst queries into structured database queries across
telemetry, incidents, action requests, and behavioral logs.

Example Queries:
- "Show all employees with high risk this week"
- "Who plugged in a USB after 10 PM?"
- "Find restricted file deletions in Finance"
- "Show pending dual-approval requests"
- "Show users with recent anomaly spikes"
"""
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from backend.models.database import Employee, Event, Alert, ActionRequest, BehavioralAnomalyLog


def execute_natural_language_investigation(db: Session, query: str) -> Dict[str, Any]:
    """Parse natural language query and retrieve matched security entities and executive summary."""
    q = (query or "").lower().strip()
    now = datetime.utcnow()
    
    matched_employees = []
    matched_events = []
    matched_requests = []
    matched_alerts = []
    matched_anomalies = []
    applied_filters = []
    intent = "GENERAL_SEARCH"

    # 1. High Risk / Suspicious Filter
    if any(k in q for k in ["high risk", "critical", "suspicious", "dangerous", "threat"]):
        intent = "RISK_SEVERITY_FILTER"
        threshold = 75 if "high" in q or "critical" in q else 50
        applied_filters.append(f"risk_score >= {threshold}")
        emps = db.query(Employee).filter(Employee.risk_score >= threshold).order_by(Employee.risk_score.desc()).all()
        matched_employees = [{"id": e.id, "name": e.name, "dept": e.department, "risk": e.risk_score, "status": e.status} for e in emps]

    # 2. USB Activity Filter
    if "usb" in q or "flash drive" in q or "external drive" in q or "thumb drive" in q:
        intent = "USB_TELEMETRY_SEARCH"
        applied_filters.append("event_type contains 'usb' OR usb_status == 'inserted'")
        events = db.query(Event).filter(or_(Event.event_type.ilike("%usb%"), Event.usb_status == "inserted")).order_by(Event.timestamp.desc()).limit(20).all()
        matched_events = [{
            "id": ev.id,
            "employee_id": ev.employee_id,
            "employee_name": ev.employee.name if ev.employee else "Unknown",
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            "type": ev.event_type,
            "details": ev.details or ev.filename,
        } for ev in events]

    # 3. Departmental filter (Finance, HR, IT, Legal, Engineering)
    depts = ["finance", "hr", "it", "legal", "engineering", "sales", "operations"]
    for d in depts:
        if d in q:
            applied_filters.append(f"department == '{d.upper()}'")
            emps = db.query(Employee).filter(Employee.department.ilike(f"%{d}%")).all()
            if emps:
                matched_employees = [{"id": e.id, "name": e.name, "dept": e.department, "risk": e.risk_score, "status": e.status} for e in emps]

    # 4. Deletions & File Interceptions (Shadow Vault)
    if "delete" in q or "deleted" in q or "vault" in q or "rollback" in q:
        intent = "DELETION_VAULT_INVESTIGATION"
        applied_filters.append("action_type == 'file_delete'")
        reqs = db.query(ActionRequest).filter(ActionRequest.action_type == "file_delete").order_by(ActionRequest.requested_at.desc()).limit(20).all()
        matched_requests = [{
            "id": r.id,
            "employee_name": r.employee.name if r.employee else "Unknown",
            "file": r.target_file,
            "path": r.file_path,
            "classification": r.file_classification,
            "risk_score": r.calculated_risk_score,
            "status": r.status,
            "requested_at": r.requested_at.isoformat() if r.requested_at else None,
        } for r in reqs]

    # 5. Pending Action Approvals / JIT
    if "approval" in q or "pending" in q or "jit" in q or "ticket" in q:
        intent = "APPROVAL_QUEUE_SEARCH"
        applied_filters.append("status IN ('PENDING', 'PARTIALLY_APPROVED')")
        pending_reqs = db.query(ActionRequest).filter(ActionRequest.status.in_(["PENDING", "PARTIALLY_APPROVED"])).order_by(ActionRequest.requested_at.desc()).all()
        matched_requests = [{
            "id": r.id,
            "employee_name": r.employee.name if r.employee else "Unknown",
            "file": r.target_file,
            "classification": r.file_classification,
            "policy": r.policy_tier,
            "approvals": f"{r.current_approvals or 0}/{r.required_approvals or 1}",
            "status": r.status,
        } for r in pending_reqs]

    # 6. Behavioral Anomalies
    if "anomaly" in q or "anomalies" in q or "deviation" in q or "off-hours" in q:
        intent = "BEHAVIORAL_ANOMALY_SEARCH"
        applied_filters.append("behavioral_anomalies score >= 40")
        anos = db.query(BehavioralAnomalyLog).filter(BehavioralAnomalyLog.anomaly_score >= 40).order_by(BehavioralAnomalyLog.detected_at.desc()).limit(20).all()
        matched_anomalies = [{
            "id": a.id,
            "employee_name": a.employee.name if a.employee else "Unknown",
            "score": a.anomaly_score,
            "severity": a.severity,
            "context": a.context,
            "detected_at": a.detected_at.isoformat() if a.detected_at else None,
        } for a in anos]

    # 7. General Employee Name Search fallback
    if not (matched_employees or matched_events or matched_requests or matched_anomalies):
        # Try matching by name
        words = q.split()
        for w in words:
            if len(w) >= 3:
                name_match = db.query(Employee).filter(Employee.name.ilike(f"%{w}%")).all()
                if name_match:
                    applied_filters.append(f"employee.name ILIKE '%{w}%'")
                    matched_employees = [{"id": e.id, "name": e.name, "dept": e.department, "risk": e.risk_score, "status": e.status} for e in name_match]
                    break

    # Build executive AI synthesis
    total_results = len(matched_employees) + len(matched_events) + len(matched_requests) + len(matched_anomalies)
    if total_results == 0:
        summary = f"No security entities matched the criteria for query: '{query}'. Try searching for 'high risk employees', 'USB activity', or 'deleted files'."
    else:
        summary = (
            f"Found **{total_results} matching security entities** for query *'{query}'* "
            f"({len(matched_employees)} employees, {len(matched_events)} telemetry events, "
            f"{len(matched_requests)} JIT action requests, {len(matched_anomalies)} behavioral anomalies)."
        )

    return {
        "query": query,
        "intent": intent,
        "applied_filters": applied_filters,
        "total_results": total_results,
        "summary": summary,
        "results": {
            "employees": matched_employees,
            "events": matched_events,
            "action_requests": matched_requests,
            "anomalies": matched_anomalies,
        }
    }
