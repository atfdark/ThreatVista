"""
ThreatVista system configuration service.

Reads/writes the single-row SystemConfig record and converts it into the
threshold dict consumed by the AI pipeline's RiskEngine.
"""
from typing import Dict

from sqlalchemy.orm import Session

from backend.models.database import SystemConfig

DEFAULTS = {
    "high_risk_threshold": 75,
    "suspicious_threshold": 50,
    "dna_window_days": 14,
    "endpoint_poll_seconds": 60,
    "monitor_files": True,
    "monitor_usb": True,
    "monitor_network": True,
    "monitor_processes": True,
}


def get_config(db: Session) -> SystemConfig:
    """Return the SystemConfig row, creating it with defaults if missing."""
    config = db.query(SystemConfig).first()
    if config is None:
        config = SystemConfig(**DEFAULTS)
        db.add(config)
        db.commit()
        db.refresh(config)
    return config


def get_thresholds(db: Session) -> Dict:
    """Return the risk classification thresholds used by the AI engine."""
    config = get_config(db)
    return {
        "suspicious_threshold": config.suspicious_threshold,
        "high_risk_threshold": config.high_risk_threshold,
    }


def to_dict(config: SystemConfig) -> Dict:
    """Serialize a SystemConfig row for the API."""
    return {
        "high_risk_threshold": config.high_risk_threshold,
        "suspicious_threshold": config.suspicious_threshold,
        "dna_window_days": config.dna_window_days,
        "endpoint_poll_seconds": config.endpoint_poll_seconds,
        "monitor_files": config.monitor_files,
        "monitor_usb": config.monitor_usb,
        "monitor_network": config.monitor_network,
        "monitor_processes": config.monitor_processes,
        "updated_at": config.updated_at.isoformat() if config.updated_at else None,
    }


def update_config(db: Session, data: Dict) -> SystemConfig:
    """Apply partial updates to the SystemConfig row."""
    config = get_config(db)
    allowed = set(DEFAULTS.keys())
    for key, value in data.items():
        if key in allowed and value is not None:
            setattr(config, key, value)
    db.commit()
    db.refresh(config)
    return config
