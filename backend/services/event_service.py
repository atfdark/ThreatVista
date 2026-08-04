from datetime import datetime
from sqlalchemy.orm import Session
from backend.models.database import Event, Employee

class EventService:
    @staticmethod
    def create_event(db: Session, event_data: dict) -> Event:
        event = Event(
            employee_id=event_data.get("employee_id"),
            timestamp=event_data.get("timestamp", datetime.utcnow()),
            event_type=event_data.get("event_type"),
            filename=event_data.get("filename"),
            extension=event_data.get("extension"),
            size=event_data.get("size"),
            folder=event_data.get("folder"),
            usb_status=event_data.get("usb_status"),
            network_upload=event_data.get("network_upload"),
            cpu_usage=event_data.get("cpu_usage"),
            ram_usage=event_data.get("ram_usage"),
            details=event_data.get("details")
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    @staticmethod
    def get_events(db: Session, skip: int = 0, limit: int = 100):
        return db.query(Event).order_by(Event.timestamp.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def get_events_by_employee(db: Session, employee_id: int, skip: int = 0, limit: int = 50):
        return db.query(Event).filter(Event.employee_id == employee_id).order_by(Event.timestamp.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def get_recent_events(db: Session, limit: int = 20):
        return db.query(Event).order_by(Event.timestamp.desc()).limit(limit).all()
