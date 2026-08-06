"""
Bulk event ingest service.

Turns an agent's ~1-second batch of events into one atomic database transaction
plus a single consolidated risk / incident / alert result that the endpoint
broadcasts as ONE WebSocket message. Every raw event is preserved in the
``events`` table.

PERFORMANCE: The batch endpoint uses ``process_batch_fast()`` which inserts
events and broadcasts them IMMEDIATELY to the dashboard, then runs the heavy
AI pipeline in a background thread so the admin sees all 150 file events
within ~1 second instead of waiting for the ML pipeline to finish.
"""
import asyncio
import threading
from datetime import datetime
from collections import defaultdict

from sqlalchemy.orm import Session

from backend.models import database as models
from backend.services.event_service import EventService
from backend.services.alert_engine import RuleBasedAlertEngine
from backend.services.config_service import get_thresholds
from backend.services import incident_service
from ai.pipeline import AIPipeline

_ai_pipeline = AIPipeline()


def run_ai_for_employee(db: Session, employee_id: int) -> dict:
    """Run the full AI pipeline for an employee's whole event history."""
    events = db.query(models.Event).filter(models.Event.employee_id == employee_id).all()
    raw = [{"id": e.id, "event_type": e.event_type, "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "size": e.size, "extension": e.extension, "folder": e.folder, "usb_status": e.usb_status,
            "network_upload": e.network_upload, "cpu_usage": e.cpu_usage, "ram_usage": e.ram_usage,
            "details": e.details} for e in events]
    thresholds = get_thresholds(db)
    return _ai_pipeline.run(raw, employee_id, thresholds)


# Throttle risk-history writes so a busy endpoint doesn't flood risk_scores.
_RISK_HISTORY_MIN_SECONDS = 300


def persist_behavior_profile(db: Session, employee_id: int, baseline: dict) -> None:
    """Upsert the employee's Behavior DNA row from a freshly computed baseline."""
    if not baseline:
        return
    profile = (
        db.query(models.BehaviorProfile)
        .filter(models.BehaviorProfile.employee_id == employee_id)
        .first()
    )
    if profile is None:
        profile = models.BehaviorProfile(employee_id=employee_id)
        db.add(profile)

    profile.working_hours_baseline = baseline.get("working_hours_baseline") or "09:00 - 17:00"
    profile.avg_usb_inserts_per_day = float(baseline.get("avg_usb_inserts_per_day") or 0)
    profile.avg_file_copies_per_day = float(baseline.get("avg_file_copies_per_day") or 0)
    profile.avg_upload_mb_per_day = float(baseline.get("avg_upload_mb_per_day") or 0)
    profile.updated_at = datetime.utcnow()


def persist_risk_history(db: Session, employee_id: int, score: int) -> None:
    """Append a risk_scores point when the score changes or enough time elapsed."""
    now = datetime.utcnow()
    last = (
        db.query(models.RiskScore)
        .filter(models.RiskScore.employee_id == employee_id)
        .order_by(models.RiskScore.recorded_at.desc())
        .first()
    )
    if last is not None:
        age = (now - last.recorded_at).total_seconds() if last.recorded_at else _RISK_HISTORY_MIN_SECONDS
        if last.score == int(score) and age < _RISK_HISTORY_MIN_SECONDS:
            return
    db.add(models.RiskScore(
        employee_id=employee_id,
        score=int(score),
        recorded_at=now,
    ))


def persist_risk_and_correlations(db: Session, employee_id: int, result: dict) -> None:
    """Persist an AI result onto the employee row + alert ledger + DNA + history.

    Updates the employee's live risk score/status, Behavior DNA baseline, risk
    progression history, and turns correlation incidents into alert rows
    (deduping exact active ones so a persisting pattern doesn't spam the
    ledger). Does NOT commit — the caller commits once after the whole batch
    is processed.
    """
    explanation = result.get("explanation", {})
    score = int(explanation.get("risk_score", 0))
    emp = db.query(models.Employee).filter(models.Employee.id == employee_id).first()
    if emp:
        emp.risk_score = score
        emp.status = explanation.get("status", "Safe")

    persist_behavior_profile(db, employee_id, result.get("baseline") or {})
    persist_risk_history(db, employee_id, score)

    for incident in result.get("correlations", []):
        reason = incident.get("reason") or incident.get("name") or "Correlation"
        dup = db.query(models.Alert).filter(
            models.Alert.employee_id == employee_id,
            models.Alert.status == "Active",
            models.Alert.reason == reason,
        ).first()
        if not dup:
            db.add(models.Alert(
                employee_id=employee_id,
                severity=incident.get("severity", "Medium"),
                reason=reason,
                status="Active",
                timestamp=datetime.utcnow(),
            ))


def _serialize_event(event: models.Event) -> dict:
    """Dict shape shared by the single-event feed and the batch payload."""
    return {
        "id": event.id,
        "employee_id": event.employee_id,
        "event_type": event.event_type,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "filename": event.filename,
        "extension": event.extension,
        "size": event.size,
        "folder": event.folder,
        "usb_status": event.usb_status,
        "network_upload": event.network_upload,
        "cpu_usage": event.cpu_usage,
        "ram_usage": event.ram_usage,
        "details": event.details,
    }


def _serialize_alert(alert: models.Alert, employee_name: str = None) -> dict:
    return {
        "id": alert.id,
        "employee_id": alert.employee_id,
        "employee": {"id": alert.employee_id, "name": employee_name or ""},
        "severity": alert.severity,
        "reason": alert.reason,
        "status": alert.status,
        "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
    }


def _pick_primary_incident(incidents: list, total_events: int) -> dict:
    """Flatten the top burst into the card-friendly ``summary`` shape."""
    if not incidents:
        return None
    top = incidents[0]
    return {
        "title": top["name"],
        "icon": top["icon"],
        "event_type": top["event_type"],
        "severity": top["severity"],
        "files": top["count"],
        "folder": top["folder"],
        "duration_seconds": top["duration_seconds"],
        "reason": top["reason"],
        "total_events": total_events,
    }


def process_batch_fast(db: Session, events_data: list[dict]) -> dict:
    """Fast-path batch ingest: insert events + broadcast IMMEDIATELY.

    Steps:
      1. Bulk insert all events (one transaction).
      2. Aggregated rule-based alerts for the batch (fast).
      3. Burst incident detection over the batch's events (fast).
      4. One commit for events + batch alerts.
      5. Return the WebSocket payload IMMEDIATELY (no AI pipeline).

    The heavy AI pipeline (risk scoring, incident lifecycle) runs later
    in a background thread via ``run_ai_background()``.
    """
    events = EventService.bulk_create(db, events_data)
    total_events = len(events)

    # 2. Aggregated rule alerts for the whole batch (at most one per trigger).
    batch_alerts = RuleBasedAlertEngine.evaluate_batch(db, events) or []

    # 3. Burst incidents over the batch (uses the freshly-flushed IDs).
    serialized = [_serialize_event(e) for e in events]
    incidents = _ai_pipeline.corr.analyze_batch(serialized)

    # Build employee name lookup from the batch.
    employees_by_id = {}
    emp_ids = {e.employee_id for e in events}
    for employee_id in emp_ids:
        emp = db.query(models.Employee).filter(models.Employee.id == employee_id).first()
        if emp:
            employees_by_id[employee_id] = emp.name

    # 4. One commit for events + batch alerts.
    db.commit()

    primary_employee_id = events[0].employee_id if events else None
    primary_employee_name = employees_by_id.get(primary_employee_id)
    alert_payloads = [_serialize_alert(a, employees_by_id.get(a.employee_id)) for a in batch_alerts]

    return {
        "summary": _pick_primary_incident(incidents, total_events),
        "employee_id": primary_employee_id,
        "employee_name": primary_employee_name,
        "total_events": total_events,
        "risk": {"score": 0, "status": "Safe", "confidence": 0},
        "alerts": alert_payloads,
        "incidents": incidents,
        "events": serialized,
        "timestamp": datetime.utcnow().isoformat(),
        "incident_changes": [],
    }


def run_ai_background(emp_ids: set, serialized_events: list, batch_alerts_data: list):
    """Run the heavy AI pipeline in a background thread, then broadcast results.

    This keeps the batch HTTP response and initial WebSocket broadcast instant
    while still computing risk scores, incidents, and correlation alerts.
    """
    from backend.database.connection import SessionLocal
    from backend.websocket.manager import manager

    def _work():
        db = SessionLocal()
        try:
            incident_changes = []
            risk_by_employee = {}

            for employee_id in emp_ids:
                try:
                    result = run_ai_for_employee(db, employee_id)
                    persist_risk_and_correlations(db, employee_id, result)
                    explanation = result.get("explanation", {})
                    risk_by_employee[employee_id] = {
                        "score": int(explanation.get("risk_score", 0)),
                        "status": explanation.get("status", "Safe"),
                        "confidence": explanation.get("confidence", 0),
                    }

                    # Build evidence from this batch's events for this employee.
                    emp_events = [ev for ev in serialized_events if ev.get("employee_id") == employee_id]
                    emp_incidents = _ai_pipeline.corr.analyze_batch(emp_events)
                    evidence = [
                        {"title": f"{inc.get('name', 'Burst activity')} ({inc.get('count', 0)} events)",
                         "detail": inc.get("reason", "")}
                        for inc in emp_incidents
                    ]
                    for alert_data in batch_alerts_data:
                        if alert_data.get("employee_id") == employee_id:
                            evidence.append({"title": f"Alert: {alert_data.get('reason', '')}", "detail": alert_data.get("severity", "")})
                    title_hint = emp_incidents[0]["name"] if emp_incidents else None

                    change = incident_service.apply_risk(db, employee_id, result,
                                                         title_hint=title_hint, evidence=evidence)
                    if change:
                        incident_changes.append({
                            "event_type": change[0],
                            "incident": incident_service.serialize(db, change[1]),
                        })
                except Exception as exc:
                    print(f"[batch-bg] AI failed for employee {employee_id}: {exc}")

            db.commit()

            # Broadcast AI results (risk updates + incident changes) via WebSocket.
            # Use broadcast_nowait from within the thread by scheduling on the
            # event loop.
            if incident_changes or risk_by_employee:
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None

                for change in incident_changes:
                    msg = {"type": change["event_type"], "data": change["incident"]}
                    if loop:
                        loop.call_soon_threadsafe(manager.broadcast_nowait, msg)

                # Broadcast a risk-update message so the dashboard can refresh
                # employee risk scores without waiting for the 15s poll.
                if risk_by_employee:
                    risk_msg = {"type": "risk_update", "data": risk_by_employee}
                    if loop:
                        loop.call_soon_threadsafe(manager.broadcast_nowait, risk_msg)

        except Exception as exc:
            print(f"[batch-bg] Background AI processing error: {exc}")
        finally:
            db.close()

    thread = threading.Thread(target=_work, name="batch-ai-bg", daemon=True)
    thread.start()


def process_batch(db: Session, events_data: list[dict]) -> dict:
    """Ingest one event batch atomically and return the WebSocket payload.

    Steps:
      1. Bulk insert all events (one transaction).
      2. Aggregated rule-based alerts for the batch.
      3. One AI pass per employee in the batch → updated risk + correlation
         alerts.
      4. Burst incident detection over the batch's events.
      5. Single commit covering events + alerts + risk.
    """
    events = EventService.bulk_create(db, events_data)
    total_events = len(events)

    # 2. Aggregated rule alerts for the whole batch (at most one per trigger).
    batch_alerts = RuleBasedAlertEngine.evaluate_batch(db, events) or []

    # 3. Burst incidents over the batch (uses the freshly-flushed IDs).
    serialized = [_serialize_event(e) for e in events]
    incidents = _ai_pipeline.corr.analyze_batch(serialized)

    # 4. AI once per employee in the batch + incident state management.
    employees_by_id = {}
    risk_by_employee = {}
    incident_changes = []
    emp_ids = {e.employee_id for e in events}
    for employee_id in emp_ids:
        emp = db.query(models.Employee).filter(models.Employee.id == employee_id).first()
        if emp:
            employees_by_id[employee_id] = emp.name
        result = run_ai_for_employee(db, employee_id)
        persist_risk_and_correlations(db, employee_id, result)
        explanation = result.get("explanation", {})
        risk_by_employee[employee_id] = {
            "score": int(explanation.get("risk_score", 0)),
            "status": explanation.get("status", "Safe"),
            "confidence": explanation.get("confidence", 0),
        }

        # New-evidence feed for this employee: their burst incidents + batch alerts.
        emp_events = [ev for ev in serialized if ev.get("employee_id") == employee_id]
        emp_incidents = _ai_pipeline.corr.analyze_batch(emp_events)
        evidence = [
            {"title": f"{inc.get('name', 'Burst activity')} ({inc.get('count', 0)} events)",
             "detail": inc.get("reason", "")}
            for inc in emp_incidents
        ]
        for alert in batch_alerts:
            if alert.employee_id == employee_id:
                evidence.append({"title": f"Alert: {alert.reason}", "detail": alert.severity})
        title_hint = emp_incidents[0]["name"] if emp_incidents else None

        change = incident_service.apply_risk(db, employee_id, result,
                                             title_hint=title_hint, evidence=evidence)
        if change:
            incident_changes.append({
                "event_type": change[0],
                "incident": incident_service.serialize(db, change[1]),
            })

    # 5. One commit for everything.
    db.commit()

    primary_employee_id = events[0].employee_id if events else None
    primary_employee_name = employees_by_id.get(primary_employee_id)
    alert_payloads = [_serialize_alert(a, employees_by_id.get(a.employee_id)) for a in batch_alerts]

    return {
        "summary": _pick_primary_incident(incidents, total_events),
        "employee_id": primary_employee_id,
        "employee_name": primary_employee_name,
        "total_events": total_events,
        "risk": risk_by_employee.get(primary_employee_id, {"score": 0, "status": "Safe", "confidence": 0}),
        "alerts": alert_payloads,
        "incidents": incidents,
        "events": serialized,
        "timestamp": datetime.utcnow().isoformat(),
        # Additive: consumed by the batch route to broadcast incident lifecycle
        # messages alongside `batch_event`. Backward-compatible with older clients.
        "incident_changes": incident_changes,
    }
