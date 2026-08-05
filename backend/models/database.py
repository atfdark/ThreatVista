from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.database.connection import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="admin")
    created_at = Column(DateTime, default=datetime.utcnow)


class Employee(Base):
    __tablename__ = "employees"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    department = Column(String, nullable=False)
    photo_url = Column(String, nullable=True)
    risk_score = Column(Integer, default=0)
    status = Column(String, default="Normal")  # Normal, Suspicious, High Risk
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    events = relationship("Event", back_populates="employee")
    alerts = relationship("Alert", back_populates="employee")
    risk_scores = relationship("RiskScore", back_populates="employee")
    behavior_profile = relationship("BehaviorProfile", back_populates="employee", uselist=False)
    devices = relationship("Device", back_populates="employee", uselist=False)
    commands = relationship("RemoteCommand", back_populates="employee")


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(Integer, ForeignKey("employees.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String, nullable=False, index=True)
    filename = Column(String, nullable=True)
    extension = Column(String, nullable=True)
    size = Column(String, nullable=True)
    folder = Column(String, nullable=True)
    usb_status = Column(String, nullable=True)
    network_upload = Column(String, nullable=True)
    cpu_usage = Column(Float, nullable=True)
    ram_usage = Column(Float, nullable=True)
    details = Column(String, nullable=True)

    employee = relationship("Employee", back_populates="events")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(Integer, ForeignKey("employees.id"), nullable=False)
    severity = Column(String, nullable=False)  # High, Medium, Low
    reason = Column(String, nullable=False)
    status = Column(String, default="Active")  # Active, Investigating, Resolved
    timestamp = Column(DateTime, default=datetime.utcnow)

    employee = relationship("Employee", back_populates="alerts")


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(Integer, ForeignKey("employees.id"), nullable=False)
    score = Column(Integer, nullable=False)
    recorded_at = Column(DateTime, default=datetime.utcnow)

    employee = relationship("Employee", back_populates="risk_scores")


class BehaviorProfile(Base):
    __tablename__ = "behavior_profiles"

    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(Integer, ForeignKey("employees.id"), unique=True, nullable=False)
    working_hours_baseline = Column(String, default="09:00 - 17:00")
    avg_usb_inserts_per_day = Column(Float, default=0.0)
    avg_file_copies_per_day = Column(Float, default=0.0)
    avg_upload_mb_per_day = Column(Float, default=0.0)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    employee = relationship("Employee", back_populates="behavior_profile")


class Session(Base):
    """Authenticated user session.

    Backs real logout / session revocation: every JWT carries a unique `jti`
    claim that references a row here. Reusing a token whose session is revoked
    or expired is rejected by the auth dependency.
    """
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    jti = Column(String, unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)
    last_seen_at = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String, nullable=True)

    user = relationship("User")


class AuditLog(Base):
    """Security audit trail for sensitive actions.

    Every meaningful state change (login, logout, settings update, alert
    transition, AI analysis trigger, report download, session revocation) is
    recorded so a Read-Only Auditor or Administrator can reconstruct who did
    what and when.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    username = Column(String, nullable=True)
    role = Column(String, nullable=True)
    action = Column(String, nullable=False, index=True)   # e.g. login, logout, alert.update
    resource = Column(String, nullable=False)              # e.g. alert, settings, report
    resource_id = Column(String, nullable=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class SystemConfig(Base):
    """Single-row configuration table for the ThreatVista engine.

    Risk index thresholds and telemetry module toggles are persisted here so
    the Settings page has a real effect on classification and ingestion.
    """
    __tablename__ = "system_config"

    id = Column(Integer, primary_key=True, index=True)
    high_risk_threshold = Column(Integer, default=75)
    suspicious_threshold = Column(Integer, default=50)
    dna_window_days = Column(Integer, default=14)
    endpoint_poll_seconds = Column(Integer, default=60)
    monitor_files = Column(Boolean, default=True)
    monitor_usb = Column(Boolean, default=True)
    monitor_network = Column(Boolean, default=True)
    monitor_processes = Column(Boolean, default=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Device(Base):
    """Endpoint device profile, one per employee.

    Registered by the endpoint agent at startup and kept alive by periodic
    heartbeats. The dashboard derives online/offline status and endpoint
    health from the most recent heartbeat.
    """
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(Integer, ForeignKey("employees.id"), unique=True, nullable=False, index=True)
    device_id = Column(String, unique=True, nullable=False, index=True)
    hostname = Column(String, nullable=True)
    os_version = Column(String, nullable=True)
    os_build = Column(String, nullable=True)
    cpu_model = Column(String, nullable=True)
    cpu_cores = Column(Integer, nullable=True)
    ram_gb = Column(Float, nullable=True)
    disk_total_gb = Column(Float, nullable=True)
    disk_free_gb = Column(Float, nullable=True)
    ip_address = Column(String, nullable=True)
    agent_version = Column(String, nullable=True)
    status = Column(String, default="offline")  # online | offline
    last_seen_at = Column(DateTime, nullable=True)
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    # Latest heartbeat snapshot (endpoint health panel)
    last_cpu_usage = Column(Float, nullable=True)
    last_ram_usage = Column(Float, nullable=True)
    last_disk_usage = Column(Float, nullable=True)

    employee = relationship("Employee", back_populates="devices")


class RemoteCommand(Base):
    """A command issued from the dashboard to an endpoint agent.

    For the hackathon these are simulated: the command is recorded so the
    dashboard can confirm the action, but no machine control is attempted.
    """
    __tablename__ = "remote_commands"

    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(Integer, ForeignKey("employees.id"), nullable=False, index=True)
    command = Column(String, nullable=False)   # disable_usb | restart_agent | collect_logs | refresh_config
    status = Column(String, default="Simulated")  # Simulated | Acknowledged
    requested_by = Column(String, nullable=True)   # dashboard username
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    employee = relationship("Employee", back_populates="commands")
