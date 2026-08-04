import sys
import os
from datetime import datetime, timedelta

# Append project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.database.connection import engine, Base, SessionLocal
from backend.models.database import User, Employee, Event, Alert, RiskScore, BehaviorProfile

def init_db():
    print("Initializing SQLite database...")
    Base.metadata.create_all(bind=engine)
    print("Tables created successfully.")

    db = SessionLocal()
    try:
        # Check if database is already seeded
        if db.query(User).first() is not None:
            print("Database already contains data. Skipping seeding.")
            return

        print("Seeding database with initial mock data...")

        # 1. Admin Users
        admin = User(
            username="admin",
            password_hash="pbkdf2:sha256:150000$mock_hash_for_admin_123", # simplified hash
            role="admin"
        )
        db.add(admin)

        # 2. Employees
        rahul = Employee(
            name="Rahul Sharma",
            email="rahul.sharma@threatvista.com",
            department="Engineering",
            photo_url="/assets/avatars/rahul.jpg",
            risk_score=92,
            status="High Risk"
        )
        amit = Employee(
            name="Amit Verma",
            email="amit.verma@threatvista.com",
            department="Sales",
            photo_url="/assets/avatars/amit.jpg",
            risk_score=63,
            status="Suspicious"
        )
        priya = Employee(
            name="Priya Patel",
            email="priya.patel@threatvista.com",
            department="Human Resources",
            photo_url="/assets/avatars/priya.jpg",
            risk_score=15,
            status="Normal"
        )
        db.add_all([rahul, amit, priya])
        db.commit() # Commit to get IDs

        # 3. Behavior Profiles (DNA)
        rahul_dna = BehaviorProfile(
            employee_id=rahul.id,
            working_hours_baseline="09:00 - 18:00",
            avg_usb_inserts_per_day=0.2,
            avg_file_copies_per_day=4.5,
            avg_upload_mb_per_day=15.0
        )
        amit_dna = BehaviorProfile(
            employee_id=amit.id,
            working_hours_baseline="10:00 - 19:00",
            avg_usb_inserts_per_day=0.5,
            avg_file_copies_per_day=12.2,
            avg_upload_mb_per_day=45.0
        )
        priya_dna = BehaviorProfile(
            employee_id=priya.id,
            working_hours_baseline="09:00 - 17:30",
            avg_usb_inserts_per_day=0.05,
            avg_file_copies_per_day=2.0,
            avg_upload_mb_per_day=5.0
        )
        db.add_all([rahul_dna, amit_dna, priya_dna])

        # 4. Risk Score History
        # Rahul's upward risk trend
        for i in range(7):
            db.add(RiskScore(
                employee_id=rahul.id,
                score=40 + i * 8 + (5 if i > 4 else 0),
                recorded_at=datetime.utcnow() - timedelta(days=7-i)
            ))
        # Amit's stable-high trend
        for i in range(7):
            db.add(RiskScore(
                employee_id=amit.id,
                score=55 + (i % 3) * 4,
                recorded_at=datetime.utcnow() - timedelta(days=7-i)
            ))
        # Priya's low-risk trend
        for i in range(7):
            db.add(RiskScore(
                employee_id=priya.id,
                score=12 + (i % 2) * 3,
                recorded_at=datetime.utcnow() - timedelta(days=7-i)
            ))

        # 5. Events
        now = datetime.utcnow()
        # Rahul's anomalous events
        db.add_all([
            Event(
                employee_id=rahul.id,
                event_type="file_copy",
                filename="report_final_v2.pdf",
                extension=".pdf",
                size="2.5MB",
                folder="Documents/Work",
                details="Copied 120 files containing keyword 'patent_design' to USB",
                timestamp=now - timedelta(hours=2)
            ),
            Event(
                employee_id=rahul.id,
                event_type="usb_insert",
                usb_status="Mass Storage Device (Kingston 64GB)",
                details="USB device connected",
                timestamp=now - timedelta(hours=2.5)
            ),
            Event(
                employee_id=rahul.id,
                event_type="network_upload",
                network_upload="1.2GB",
                cpu_usage=45.2,
                ram_usage=62.1,
                details="Uploaded 1.2 GB of ZIP data to unknown external IP",
                timestamp=now - timedelta(hours=4)
            ),
            Event(
                employee_id=rahul.id,
                event_type="process_start",
                details="Ran cmd.exe to edit file attributes",
                timestamp=now - timedelta(hours=4.5)
            )
        ])

        # Amit's events
        db.add_all([
            Event(
                employee_id=amit.id,
                event_type="login",
                details="System access detected at 02:45 AM (Out-of-office hours)",
                timestamp=now - timedelta(hours=18)
            ),
            Event(
                employee_id=amit.id,
                event_type="file_access",
                filename="employee_contacts_confidential.xlsx",
                extension=".xlsx",
                folder="HR/Confidential",
                details="Accessed employee_contacts_confidential.xlsx",
                timestamp=now - timedelta(hours=17.5)
            ),
            Event(
                employee_id=amit.id,
                event_type="usb_insert",
                usb_status="Generic Flash Device",
                details="Unrecognized USB Device connected",
                timestamp=now - timedelta(hours=17.2)
            )
        ])

        # Priya's events
        db.add_all([
            Event(
                employee_id=priya.id,
                event_type="file_access",
                filename="performance_evaluation_Q2.docx",
                extension=".docx",
                folder="HR/Reviews",
                details="Modified performance_evaluation_Q2.docx",
                timestamp=now - timedelta(hours=3)
            ),
            Event(
                employee_id=priya.id,
                event_type="login",
                details="Logged in at 09:02 AM",
                timestamp=now - timedelta(hours=10)
            )
        ])

        # 6. Alerts
        db.add_all([
            Alert(
                employee_id=rahul.id,
                severity="High",
                reason="Correlation: Mass file copying of patent data (120 files) following external network upload (1.2GB) and USB insertion.",
                status="Active",
                timestamp=now - timedelta(hours=2)
            ),
            Alert(
                employee_id=rahul.id,
                severity="Medium",
                reason="Unusual network upload volume (1.2 GB, baseline: 15 MB/day)",
                status="Active",
                timestamp=now - timedelta(hours=4)
            ),
            Alert(
                employee_id=amit.id,
                severity="High",
                reason="Late night login at 02:45 AM followed by access to restricted sales and employee contact spreadsheets.",
                status="Investigating",
                timestamp=now - timedelta(hours=17.5)
            )
        ])

        db.commit()
        print("Mock data seeded successfully!")

    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
        raise e
    finally:
        db.close()

if __name__ == "__main__":
    init_db()
