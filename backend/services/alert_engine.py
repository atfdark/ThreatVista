from datetime import datetime, timedelta
from typing import Optional, List
from sqlalchemy.orm import Session
from backend.models.database import Event, Alert, Employee
from ai.features import TIMEZONE_OFFSET_HOURS
from ai.sensitive_scanner import SensitiveAssetScanner

class RuleBasedAlertEngine:
    USB_INSERT_RISK = 25
    OFFICE_HOURS_START = 9
    OFFICE_HOURS_END = 18
    HIGH_FILE_COPY_THRESHOLD = 100

    @staticmethod
    def evaluate_event(db: Session, event: Event) -> Optional[List[Alert]]:
        alerts_created = []

        # 1. Sensitive Asset Movement Check
        if (event.event_type or "").startswith("file_") or (event.event_type or "").startswith("folder_"):
            res = SensitiveAssetScanner.match_file(
                filename=event.filename,
                folder=event.folder,
                extension=event.extension,
                details=event.details,
                db=db
            )
            if res["is_sensitive"]:
                sev = "Critical" if res["is_sensitive_zip"] else ("High" if res["match_count"] >= 2 else "Medium")
                kw_str = ", ".join(res["matched_keywords"])
                alert = Alert(
                    employee_id=event.employee_id,
                    severity=sev,
                    reason=f"Sensitive Asset Movement: '{res['filename']}' matched keyword(s) {kw_str} (+{res['risk_added']} risk)",
                    status="Active",
                    timestamp=datetime.utcnow()
                )
                db.add(alert)
                alerts_created.append(alert)

        # 2. USB insert
        if event.event_type == "usb_insert":
            alert = Alert(
                employee_id=event.employee_id,
                severity="Medium",
                reason=f"USB Activity Detected: {event.usb_status or 'Removable Storage Device'}",
                status="Active",
                timestamp=datetime.utcnow()
            )
            db.add(alert)
            alerts_created.append(alert)

        # 3. Off-hours activity
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

        # 4. Mass file copies
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
        """
        if not events:
            return None

        alerts_created = []
        reasons_seen = set()

        # Sensitive asset detection in batch
        sensitive_events = []
        for e in events:
            if (e.event_type or "").startswith("file_") or (e.event_type or "").startswith("folder_"):
                res = SensitiveAssetScanner.match_file(
                    filename=e.filename,
                    folder=e.folder,
                    extension=e.extension,
                    details=e.details,
                    db=db
                )
                if res["is_sensitive"]:
                    sensitive_events.append((e, res))

        if sensitive_events:
            all_kws = set()
            has_zip = False
            for _, r in sensitive_events:
                all_kws.update(r["matched_keywords"])
                if r["is_sensitive_zip"]:
                    has_zip = True
            
            sev = "Critical" if has_zip else ("High" if len(all_kws) >= 2 else "Medium")
            kw_str = ", ".join(sorted(all_kws)[:4])
            reason = f"Sensitive Asset Movement: {len(sensitive_events)} file operation(s) matched keywords ({kw_str})"
            if reason not in reasons_seen:
                reasons_seen.add(reason)
                alerts_created.append(Alert(
                    employee_id=events[0].employee_id,
                    severity=sev,
                    reason=reason,
                    status="Active",
                    timestamp=datetime.utcnow(),
                ))

        # USB inserted in this batch
        usb_inserts = [e for e in events if e.event_type == "usb_insert"]
        if usb_inserts:
            device = usb_inserts[0].usb_status or "Removable Storage Device"
            reason = f"USB Activity Detected: {device}"
            if reason not in reasons_seen:
                reasons_seen.add(reason)
                alerts_created.append(Alert(
                    employee_id=usb_inserts[0].employee_id,
                    severity="Medium",
                    reason=reason,
                    status="Active",
                    timestamp=datetime.utcnow(),
                ))

        # Out-of-office login / process activity in this batch
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

        # Mass file operations in a single batch
        file_ops = [e for e in events if (e.event_type or "").startswith("file_")]
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
