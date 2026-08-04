from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session
from backend.models.database import Event, Alert, Employee

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
                hour = event.timestamp.hour
                if hour < RuleBasedAlertEngine.OFFICE_HOURS_START or hour >= RuleBasedAlertEngine.OFFICE_HOURS_END:
                    alert = Alert(
                        employee_id=event.employee_id,
                        severity="Medium",
                        reason=f"Activity detected outside office hours at {event.timestamp.strftime('%H:%M')}",
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
