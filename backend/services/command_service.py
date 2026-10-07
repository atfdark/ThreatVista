"""
ThreatVista remote-command service.

For the hackathon, commands are **simulated**: they are recorded so the
dashboard can confirm the action, but nothing is sent to the endpoint machine.
"""
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from backend.models.database import Employee, RemoteCommand

# Allowed command types surfaced by the dashboard.
ALLOWED_COMMANDS = {
    "disable_usb": "Disable USB mass storage on endpoint",
    "enable_usb": "Re-enable USB mass storage on endpoint",
    "readonly_usb": "Enable USB mass storage write protection (Read-Only)",
    "readwrite_usb": "Disable USB mass storage write protection (Read/Write)",
    "restart_agent": "Restart ThreatVista agent service",
    "collect_logs": "Collect detailed process & event logs (24h)",
    "refresh_config": "Refresh endpoint monitoring configuration",
    "execute_approved_action": "Execute authorized JIT action on endpoint",
}


def request_command(
    db: Session,
    employee_id: int,
    command: str,
    requested_by: Optional[str] = None,
    details: Optional[str] = None,
) -> Dict:
    """Record a dashboard command for an employee."""
    employee = db.query(Employee).filter(Employee.id == employee_id).first()
    if not employee:
        raise ValueError(f"Employee {employee_id} not found")
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"Unknown command '{command}'. Allowed: {list(ALLOWED_COMMANDS)}")

    cmd = RemoteCommand(
        employee_id=employee_id,
        command=command,
        status="Pending",
        requested_by=requested_by or "dashboard",
        details=details or ALLOWED_COMMANDS[command],
    )

    db.add(cmd)
    db.commit()
    db.refresh(cmd)
    return command_to_dict(cmd)


def list_commands(db: Session, employee_id: int, limit: int = 20) -> List[Dict]:
    commands = (
        db.query(RemoteCommand)
        .filter(RemoteCommand.employee_id == employee_id)
        .order_by(RemoteCommand.created_at.desc())
        .limit(limit)
        .all()
    )
    return [command_to_dict(c) for c in commands]


def command_to_dict(cmd: RemoteCommand) -> Dict:
    return {
        "id": cmd.id,
        "employee_id": cmd.employee_id,
        "command": cmd.command,
        "label": ALLOWED_COMMANDS.get(cmd.command, cmd.command),
        "status": cmd.status,
        "requested_by": cmd.requested_by,
        "details": cmd.details,
        "created_at": cmd.created_at.isoformat() if cmd.created_at else None,
        "completed_at": cmd.completed_at.isoformat() if cmd.completed_at else None,
    }
