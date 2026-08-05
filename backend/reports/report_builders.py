"""
ThreatVista report builders.

Each builder computes one report type purely from the local telemetry tables
(Event / RiskScore / Alert / Employee). No AI pipeline runs — reports are cheap
even while the dashboard streams live events.
"""
import re
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from backend.models.database import Alert, Employee, Event, RiskScore


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _parse_dt(value):
    """Parse 'YYYY-MM-DD' or full ISO timestamps to a naive datetime."""
    if not value:
        return None
    v = str(value).strip()
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _parse_range(start, end, default_days=7):
    """Resolve an inclusive [start, end] window in UTC (naive datetimes)."""
    now = datetime.utcnow()
    start_dt = _parse_dt(start) if start else (now - timedelta(days=default_days))
    end_dt = _parse_dt(end) if end else now
    if start_dt > end_dt:
        raise ValueError("start date must be before end date")
    if end_dt > now:
        end_dt = now
    return start_dt, end_dt


def _period_str(start_dt, end_dt):
    return f"{start_dt.strftime('%Y-%m-%d %H:%M')} to {end_dt.strftime('%Y-%m-%d %H:%M')}"


def _events(db: Session, start_dt, end_dt):
    return (
        db.query(Event)
        .filter(Event.timestamp >= start_dt, Event.timestamp <= end_dt)
        .order_by(Event.timestamp.asc())
        .all()
    )


def _alerts(db: Session, start_dt, end_dt):
    return (
        db.query(Alert)
        .filter(Alert.timestamp >= start_dt, Alert.timestamp <= end_dt)
        .order_by(Alert.timestamp.asc())
        .all()
    )


def _risk_scores(db: Session, start_dt, end_dt):
    return (
        db.query(RiskScore)
        .filter(RiskScore.recorded_at >= start_dt, RiskScore.recorded_at <= end_dt)
        .all()
    )


def _employees(db: Session):
    return db.query(Employee).all()


def _parse_mb(val):
    """Convert '1.2GB' / '512MB' style sizes to megabytes."""
    if val is None:
        return 0.0
    m = re.match(r"([0-9.]+)\s*(MB|GB|KB|B|TB)?", str(val).strip().upper())
    if not m:
        return 0.0
    v, unit = float(m.group(1)), (m.group(2) or "B")
    if unit == "GB":
        return v * 1024
    if unit == "TB":
        return v * 1024 * 1024
    if unit == "KB":
        return v / 1024
    if unit == "B":
        return v / (1024 * 1024)
    return v


def _employee_map(db: Session):
    return {emp.id: emp for emp in _employees(db)}


def _daily_trends(events, risk_scores, alerts, start_dt, end_dt):
    """Bucket events / risk scores / alerts by day for the requested window."""
    per_day = defaultdict(lambda: {"event_count": 0, "risk_sum": 0, "risk_n": 0, "new_alerts": 0})

    for e in events:
        if e.timestamp:
            per_day[e.timestamp.date()]["event_count"] += 1
    for r in risk_scores:
        if r.recorded_at:
            day = per_day[r.recorded_at.date()]
            day["risk_sum"] += r.score
            day["risk_n"] += 1
    for a in alerts:
        if a.timestamp:
            per_day[a.timestamp.date()]["new_alerts"] += 1

    trends = []
    day = start_dt.date()
    while day <= end_dt.date():
        d = per_day[day]  # defaultdict factory fills empty days with zeros
        trends.append({
            "date": day.isoformat(),
            "event_count": d["event_count"],
            "avg_risk": round(d["risk_sum"] / d["risk_n"], 1) if d["risk_n"] else 0,
            "new_alerts": d["new_alerts"],
        })
        day += timedelta(days=1)
    return trends


def _rec(employee, event_type):
    """Compact CSV-friendly event row."""
    return {
        "employee_id": event_type.employee_id,
        "employee": employee.name if employee else f"#{event_type.employee_id}",
        "department": employee.department if employee else "",
        "event_type": event_type.event_type,
        "timestamp": event_type.timestamp.isoformat() if event_type.timestamp else "",
        "filename": event_type.filename or "",
        "folder": event_type.folder or "",
        "size": event_type.size or "",
        "details": (event_type.details or "")[:120],
    }


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def _build_daily_threat(db, start, end):
    start_dt, end_dt = _parse_range(start, end, default_days=1)
    events = _events(db, start_dt, end_dt)
    alerts = _alerts(db, start_dt, end_dt)
    risk_scores = _risk_scores(db, start_dt, end_dt)
    emap = _employee_map(db)

    high_risk = [e for e in _employees(db) if (e.risk_score or 0) > 75]
    avg_risk = sum(e.risk_score or 0 for e in _employees(db)) / len(_employees(db)) if _employees(db) else 0

    rows = [
        {
            "alert_id": a.id,
            "employee": emap[a.employee_id].name if a.employee_id in emap else f"#{a.employee_id}",
            "severity": a.severity,
            "status": a.status,
            "reason": a.reason,
            "timestamp": a.timestamp.isoformat() if a.timestamp else "",
        }
        for a in alerts
    ]
    return {
        "title": "Daily Threat Report",
        "report_type": "daily_threat",
        "period": _period_str(start_dt, end_dt),
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "events": len(events),
            "alerts": len(alerts),
            "active_alerts": sum(1 for a in alerts if a.status == "Active"),
            "high_risk_employees": len(high_risk),
            "avg_risk": round(avg_risk, 1),
        },
        "rows": rows,
        "trends": _daily_trends(events, risk_scores, alerts, start_dt, end_dt),
        "recommendations": _daily_recommendations(high_risk, alerts),
    }


def _daily_recommendations(high_risk, alerts):
    recs = []
    if high_risk:
        names = ", ".join(e.name for e in high_risk[:3])
        recs.append(f"Review {len(high_risk)} high-risk profile(s): {names}. Restrict USB and external upload access.")
    critical = [a for a in alerts if a.severity == "High"]
    if critical:
        recs.append(f"{len(critical)} High-severity alert(s) today — investigate and transition to Resolved when closed.")
    if not recs:
        recs.append("No notable events. Continue standard baseline monitoring.")
    return recs


def _build_weekly_activity(db, start, end):
    start_dt, end_dt = _parse_range(start, end, default_days=7)
    events = _events(db, start_dt, end_dt)
    alerts = _alerts(db, start_dt, end_dt)
    risk_scores = _risk_scores(db, start_dt, end_dt)
    emap = _employee_map(db)

    per_emp = defaultdict(lambda: {"events": 0, "alerts": 0})
    for e in events:
        per_emp[e.employee_id]["events"] += 1
    for a in alerts:
        per_emp[a.employee_id]["alerts"] += 1

    dept_events = defaultdict(int)
    for e in events:
        emp = emap.get(e.employee_id)
        if emp:
            dept_events[emp.department] += 1

    rows = []
    for emp in _employees(db):
        agg = per_emp[emp.id]
        rows.append({
            "employee_id": emp.id,
            "employee": emp.name,
            "department": emp.department,
            "events": agg["events"],
            "alerts": agg["alerts"],
            "risk_score": emp.risk_score or 0,
            "status": emp.status,
        })
    rows.sort(key=lambda r: r["risk_score"], reverse=True)

    top_dept = max(dept_events, key=dept_events.get) if dept_events else "—"
    return {
        "title": "Weekly Activity Report",
        "report_type": "weekly_activity",
        "period": _period_str(start_dt, end_dt),
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_events": len(events),
            "total_alerts": len(alerts),
            "active_alerts": sum(1 for a in alerts if a.status == "Active"),
            "monitored_employees": len(_employees(db)),
            "top_department": top_dept,
        },
        "rows": rows,
        "trends": _daily_trends(events, risk_scores, alerts, start_dt, end_dt),
        "recommendations": [
            f"Focus next week on the highest-risk employee(s): {', '.join(r['employee'] for r in rows[:2])}."
            if rows else "No activity to summarize.",
            "Re-baseline Behavior DNA for employees whose risk trended upward this week."
        ],
    }


def _build_monthly_summary(db, start, end):
    start_dt, end_dt = _parse_range(start, end, default_days=30)
    events = _events(db, start_dt, end_dt)
    alerts = _alerts(db, start_dt, end_dt)
    risk_scores = _risk_scores(db, start_dt, end_dt)

    employees = _employees(db)
    per_emp = defaultdict(lambda: {"events": 0, "alerts": 0})
    for e in events:
        per_emp[e.employee_id]["events"] += 1
    for a in alerts:
        per_emp[a.employee_id]["alerts"] += 1

    dist = {"Low (0-30)": 0, "Medium (31-60)": 0, "High (61-80)": 0, "Critical (81-100)": 0}
    for emp in employees:
        s = emp.risk_score or 0
        if s <= 30:
            dist["Low (0-30)"] += 1
        elif s <= 60:
            dist["Medium (31-60)"] += 1
        elif s <= 80:
            dist["High (61-80)"] += 1
        else:
            dist["Critical (81-100)"] += 1

    rows = [
        {
            "employee_id": emp.id,
            "employee": emp.name,
            "department": emp.department,
            "events": per_emp[emp.id]["events"],
            "alerts": per_emp[emp.id]["alerts"],
            "risk_score": emp.risk_score or 0,
            "status": emp.status,
        }
        for emp in employees
    ]
    rows.sort(key=lambda r: r["risk_score"], reverse=True)

    return {
        "title": "Monthly Security Summary",
        "report_type": "monthly_summary",
        "period": _period_str(start_dt, end_dt),
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_events": len(events),
            "total_alerts": len(alerts),
            "risk_distribution": dist,
            "high_risk": sum(1 for e in employees if (e.risk_score or 0) > 60),
        },
        "rows": rows,
        "trends": _daily_trends(events, risk_scores, alerts, start_dt, end_dt),
        "recommendations": [
            f"Critical profiles this month: {sum(1 for e in employees if (e.risk_score or 0) > 80)}."
            " Schedule reviews and tighten exfiltration controls for trending employees.",
            "Archive this summary and include it in the leadership security briefing."
        ],
    }


def _build_high_risk_employees(db, start, end):
    start_dt, end_dt = _parse_range(start, end, default_days=7)
    employees = _employees(db)
    flagged = [e for e in employees if (e.risk_score or 0) >= 50]
    flagged.sort(key=lambda e: e.risk_score or 0, reverse=True)

    alerts = _alerts(db, start_dt, end_dt)
    alert_counts = defaultdict(int)
    for a in alerts:
        alert_counts[a.employee_id] += 1

    rows = [
        {
            "employee_id": e.id,
            "employee": e.name,
            "department": e.department,
            "risk_score": e.risk_score or 0,
            "status": e.status,
            "open_alerts": alert_counts.get(e.id, 0),
        }
        for e in flagged
    ]
    return {
        "title": "High-Risk Employee Report",
        "report_type": "high_risk_employees",
        "period": _period_str(start_dt, end_dt),
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "flagged": len(flagged),
            "critical": sum(1 for e in flagged if (e.risk_score or 0) > 80),
            "monitored": len(employees),
        },
        "rows": rows,
        "trends": _daily_trends([], _risk_scores(db, start_dt, end_dt), alerts, start_dt, end_dt),
        "recommendations": [
            "Immediately re-review flagged profiles and lock down USB / external upload paths.",
            "Trigger audit-log extraction and Behavior DNA re-baselining for each flagged employee.",
            "Escalate persistent Critical profiles to HR and management for a formal review.",
        ],
    }


def _build_usb_usage(db, start, end):
    start_dt, end_dt = _parse_range(start, end, default_days=7)
    events = [e for e in _events(db, start_dt, end_dt) if e.event_type in ("usb_insert", "usb_remove")]
    emap = _employee_map(db)

    rows = [
        {
            "employee_id": e.employee_id,
            "employee": emap[e.employee_id].name if e.employee_id in emap else f"#{e.employee_id}",
            "event_type": e.event_type,
            "usb_status": e.usb_status or "",
            "details": (e.details or "")[:100],
            "timestamp": e.timestamp.isoformat() if e.timestamp else "",
        }
        for e in events
    ]
    inserts = [e for e in events if e.event_type == "usb_insert"]
    return {
        "title": "USB Usage Report",
        "report_type": "usb_usage",
        "period": _period_str(start_dt, end_dt),
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "usb_events": len(events),
            "usb_inserts": len(inserts),
            "usb_removals": len(events) - len(inserts),
            "distinct_employees": len({e.employee_id for e in events}),
        },
        "rows": rows,
        "trends": _daily_trends(events, [], [], start_dt, end_dt),
        "recommendations": [
            "USB insertions outside working hours merit review for data staging.",
            "If USB policy is allowlist-only, verify each device against the approved list."
        ],
    }


def _build_file_activity(db, start, end):
    start_dt, end_dt = _parse_range(start, end, default_days=7)
    file_types = ("file_copy", "file_create", "file_modify", "file_delete", "file_rename", "file_move", "file_access")
    events = [e for e in _events(db, start_dt, end_dt) if e.event_type in file_types]
    emap = _employee_map(db)

    by_type = defaultdict(int)
    for e in events:
        by_type[e.event_type] += 1

    rows = [_rec(emap.get(e.employee_id), e) for e in events]
    return {
        "title": "File Activity Report",
        "report_type": "file_activity",
        "period": _period_str(start_dt, end_dt),
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "file_operations": len(events),
            "copies": by_type.get("file_copy", 0),
            "deletes": by_type.get("file_delete", 0),
            "creates": by_type.get("file_create", 0),
            "modifies": by_type.get("file_modify", 0),
            "distinct_employees": len({e.employee_id for e in events}),
        },
        "rows": rows,
        "trends": _daily_trends(events, [], [], start_dt, end_dt),
        "recommendations": [
            "Large copy + delete sequences may indicate data staging followed by cover-up.",
            "Correlate mass file activity with USB and network events before escalating."
        ],
    }


def _build_network_activity(db, start, end):
    start_dt, end_dt = _parse_range(start, end, default_days=7)
    events = [e for e in _events(db, start_dt, end_dt) if e.event_type == "network_upload"]
    emap = _employee_map(db)

    total_mb = sum(_parse_mb(e.network_upload) for e in events)
    rows = []
    for e in events:
        rows.append({
            "employee_id": e.employee_id,
            "employee": emap[e.employee_id].name if e.employee_id in emap else f"#{e.employee_id}",
            "upload_mb": round(_parse_mb(e.network_upload), 1),
            "details": (e.details or "")[:100],
            "timestamp": e.timestamp.isoformat() if e.timestamp else "",
        })
    return {
        "title": "Network Activity Report",
        "report_type": "network_activity",
        "period": _period_str(start_dt, end_dt),
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "uploads": len(events),
            "total_upload_mb": round(total_mb, 1),
            "largest_mb": round(max((_parse_mb(e.network_upload) for e in events), default=0.0), 1),
            "distinct_employees": len({e.employee_id for e in events}),
        },
        "rows": rows,
        "trends": _daily_trends(events, [], [], start_dt, end_dt),
        "recommendations": [
            "Uploads far above the employee's Behavior DNA baseline suggest exfiltration.",
            "Night / weekend uploads to unknown external IPs should be investigated promptly."
        ],
    }


BUILDERS = {
    "daily_threat": _build_daily_threat,
    "weekly_activity": _build_weekly_activity,
    "monthly_summary": _build_monthly_summary,
    "high_risk_employees": _build_high_risk_employees,
    "usb_usage": _build_usb_usage,
    "file_activity": _build_file_activity,
    "network_activity": _build_network_activity,
}
