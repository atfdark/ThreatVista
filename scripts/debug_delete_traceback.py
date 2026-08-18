import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.database.connection import SessionLocal
from backend.models import database as models

def debug_delete():
    db = SessionLocal()
    try:
        emp = db.query(models.Employee).filter(models.Employee.name == "Demo Candidate").first()
        if not emp:
            print("No Demo Candidate found")
            return
        employee_id = emp.id
        print(f"Found employee: id={employee_id}")

        incidents = db.query(models.Incident).filter(models.Incident.employee_id == employee_id).all()
        for inc in incidents:
            db.query(models.IncidentTimeline).filter(models.IncidentTimeline.incident_id == inc.id).delete()
            db.delete(inc)

        db.query(models.Event).filter(models.Event.employee_id == employee_id).delete()
        db.query(models.Alert).filter(models.Alert.employee_id == employee_id).delete()
        db.query(models.RiskScore).filter(models.RiskScore.employee_id == employee_id).delete()
        db.query(models.BehaviorProfile).filter(models.BehaviorProfile.employee_id == employee_id).delete()
        db.query(models.RemoteCommand).filter(models.RemoteCommand.employee_id == employee_id).delete()
        db.query(models.AgentEnrollmentToken).filter(models.AgentEnrollmentToken.employee_id == employee_id).delete()
        db.query(models.Device).filter(models.Device.employee_id == employee_id).delete()

        user_account = db.query(models.User).filter(
            (models.User.username == emp.email) | (models.User.username == emp.name)
        ).first()
        if user_account:
            db.query(models.Session).filter(models.Session.user_id == user_account.id).delete()
            db.delete(user_account)

        db.delete(emp)
        db.commit()
        print("✓ Employee deleted successfully in local session!")
    except Exception as e:
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    debug_delete()
