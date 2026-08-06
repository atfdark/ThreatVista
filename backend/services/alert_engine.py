from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from backend.models.database import Event, Alert, Employee

# Same timezone the risk features use (IST by default). Event timestamps are
# stored in UTC, so the office-hours check must shift them into local time the
# same way ai/features.py does — otherwise a midday UTC event (e.g. 07:00 UTC
# = 12:30 IST) is wrongly flagged as "outside office hours".
from ai.features import TIMEZONE_OFFSET_HOURS

class RuleBasedAlertEngine:
    USB_INSERT_RISK = 25
    OFFICE_HOURS_START = 9
    OFFICE_HOURS_END = 18
    HIGH_FILE_COPY_THRESHOLD = 100

    @staticmethod
    def evaluate_event(db: Session, event: Event) -> Optional[Alert]:
        alerts_created = []

        if event.event_type == "usb_insert":
            alert = Alert(
                employee_id=event.employee_id,
                severity="Medium",
                reason=f"USB device inserted: {event.usb_status or 'Unknown device'}",
                status="Active",
                timestamp=datetime.utcnow()
            )
            db.add(alert)
            alerts_created.append(alert)

        if event.event_type in ("login", "process_start"):
            if event.timestamp:
                local = event.timestamp + timedelta(hours=TIMEZONE_OFFSET_HOURS)
                hour = local.hour
                if hour < RuleBasedAlertEngine.OFFICE_HOURS_START or hour >= RuleBasedAlertEngine.OFFICE_HOURS_END:
                    alert = Alert(
                        employee_id=event.employee_id,
                        severity="Medium",
                        reason=f"Activity detected outside office hours at {local.strftime('%H:%M')}",
                        status="Active",
                        timestamp=datetime.utcnow()
                    )
                    db.add(alert)
                    alerts_created.append(alert)

        if event.event_type == "file_copy":
            employee = db.query(Employee).filter(Employee.id == event.employee_id).first()
            if employee:
                recent_copies = db.query(Event).filter(
                    Event.employee_id == event.employee_id,
                    Event.event_type == "file_copy",
                    Event.timestamp >= datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
                ).count()
                if recent_copies > RuleBasedAlertEngine.HIGH_FILE_COPY_THRESHOLD:
                    alert = Alert(
                        employee_id=event.employee_id,
                        severity="High",
                        reason=f"Mass file operations detected: {recent_copies} copies in last 24 hours",
                        status="Active",
                        timestamp=datetime.utcnow()
                    )
                    db.add(alert)
                    alerts_created.append(alert)

        return alerts_created if alerts_created else None

    @staticmethod
    def evaluate_batch(db: Session, events: list) -> Optional[list]:
        """Evaluate a whole event batch as one unit and emit at most one alert
        per trigger.

        Runs after a bulk ingest so a 150-file burst produces a handful of
        aggregated alerts instead of 150 near-identical rows. Adds the alerts to
        the session but does NOT commit — the batch endpoint commits once.
        """
        if not events:
            return None

        alerts_created = []
        reasons_seen = set()

        # USB inserted in this batch.
        usb_inserts = [e for e in events if e.event_type == "usb_insert"]
        if usb_inserts:
            device = usb_inserts[0].usb_status or "Unknown device"
            reason = f"USB device inserted: {device}"
            if reason not in reasons_seen:
                reasons_seen.add(reason)
                alerts_created.append(Alert(
                    employee_id=usb_inserts[0].employee_id,
                    severity="Medium",
                    reason=reason,
                    status="Active",
                    timestamp=datetime.utcnow(),
                ))

        # Out-of-office login / process activity in this batch (IST-aware, same
        # timezone shift the single-event rules and ai/features.py use).
        outside = False
        for e in events:
            if e.event_type in ("login", "process_start") and e.timestamp:
                local = e.timestamp + timedelta(hours=TIMEZONE_OFFSET_HOURS)
                if local.hour < RuleBasedAlertEngine.OFFICE_HOURS_START or local.hour >= RuleBasedAlertEngine.OFFICE_HOURS_END:
                    outside = True
                    break
        if outside:
            reason = "Activity detected outside office hours"
            if reason not in reasons_seen:
                reasons_seen.add(reason)
                alerts_created.append(Alert(
                    employee_id=events[0].employee_id,
                    severity="Medium",
                    reason=reason,
                    status="Active",
                    timestamp=datetime.utcnow(),
                ))

        # Mass file operations in a single batch.
        file_ops = [e for e in events if e.event_type.startswith("file_")]
        if len(file_ops) > RuleBasedAlertEngine.HIGH_FILE_COPY_THRESHOLD:
            reason = f"Mass file operations detected: {len(file_ops)} in one batch"
            if reason not in reasons_seen:
                reasons_seen.add(reason)
                alerts_created.append(Alert(
                    employee_id=file_ops[0].employee_id,
                    severity="High",
                    reason=reason,
                    status="Active",
                    timestamp=datetime.utcnow(),
                ))

        return alerts_created if alerts_created else None
