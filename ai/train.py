import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai.pipeline import AIPipeline
from ai.model import AnomalyModel
from backend.database.connection import SessionLocal
from backend.models.database import Event, Employee
import numpy as np

def train_from_db():
    db = SessionLocal()
    try:
        employees = db.query(Employee).all()
        model = AnomalyModel()
        matrices = []
        pipeline = AIPipeline(db)
        for emp in employees:
            events = db.query(Event).filter(Event.employee_id == emp.id).all()
            raw = [{"id": e.id, "event_type": e.event_type, "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "size": e.size, "extension": e.extension, "folder": e.folder, "usb_status": e.usb_status,
                    "network_upload": e.network_upload, "cpu_usage": e.cpu_usage, "ram_usage": e.ram_usage,
                    "details": e.details} for e in events]
            result = pipeline.run(raw, emp.id)
            vec = [result["features"].get(k, 0) for k in model.feature_names]
            matrices.append(vec)
        if matrices:
            model.train(np.array(matrices))
            print(f"Model trained on {len(matrices)} samples")
        else:
            print("No data to train")
    finally:
        db.close()

if __name__ == "__main__":
    train_from_db()
