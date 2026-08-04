from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey
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
