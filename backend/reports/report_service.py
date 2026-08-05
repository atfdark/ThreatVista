"""
ThreatVista report service.

Entry point for generating any report type. Returns a structured dict
(title, period, generated_at, summary, rows, trends, recommendations) that the
API route renders as JSON, CSV, or printable HTML.
"""
from sqlalchemy.orm import Session

from backend.reports.report_builders import BUILDERS

REPORT_TYPES = {
    "daily_threat": "Daily Threat Report",
    "weekly_activity": "Weekly Activity Report",
    "monthly_summary": "Monthly Security Summary",
    "high_risk_employees": "High-Risk Employee Report",
    "usb_usage": "USB Usage Report",
    "file_activity": "File Activity Report",
    "network_activity": "Network Activity Report",
}


def generate_report(db: Session, report_type: str, start=None, end=None) -> dict:
    """Build the report dict for ``report_type`` over [start, end] (ISO dates)."""
    if report_type not in BUILDERS:
        raise ValueError(f"Unknown report type: {report_type}")
    return BUILDERS[report_type](db, start=start, end=end)
