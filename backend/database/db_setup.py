import sys
import os
from datetime import datetime, timedelta

# Append project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.database.connection import engine, Base, SessionLocal
from backend.models.database import User, Employee, Event, Alert, RiskScore, BehaviorProfile, SystemConfig, Device, SeedState
from backend.auth import hash_password, verify_password

def ensure_admin_hash(db):
    """Migrate a legacy mock password hash to a real bcrypt hash."""
    admin = db.query(User).filter(User.username == "admin").first()
    if admin and not admin.password_hash.startswith("$2"):
        try:
            admin.password_hash = hash_password("admin123")
            db.commit()
            print("[+] Migrated admin password hash to bcrypt.")
        except Exception as e:
            print(f"[!] Could not migrate admin hash: {e}")


def ensure_admin(db):
    """Ensure the 'admin' account exists (needed even in empty-seed mode)."""
    if db.query(User).filter(User.username == "admin").first() is None:
        db.add(User(username="admin", password_hash=hash_password("admin123"), role="admin"))
        db.commit()
        print("[+] Seeded 'admin' account.")


def ensure_analyst(db):
    """Ensure the demo 'analyst' account exists (role-based access control)."""
    if db.query(User).filter(User.username == "analyst").first() is None:
        db.add(User(username="analyst", password_hash=hash_password("analyst123"), role="analyst"))
        db.commit()
        print("[+] Seeded 'analyst' demo account.")

def ensure_auditor(db):
    """Ensure the read-only 'auditor' demo account exists (RBAC)."""
    if db.query(User).filter(User.username == "auditor").first() is None:
        db.add(User(username="auditor", password_hash=hash_password("auditor123"), role="auditor"))
        db.commit()
        print("[+] Seeded 'auditor' demo account.")

def ensure_system_config(db):
    """Ensure a SystemConfig row exists (created with defaults)."""
    if db.query(SystemConfig).first() is None:
        db.add(SystemConfig())
        db.commit()
        print("[+] Seeded system configuration defaults.")

def ensure_employee_role_column(db):
    """Ensure role_type column exists on employees table in SQLite."""
    try:
        from sqlalchemy import text
        res = db.execute(text("PRAGMA table_info(employees)")).fetchall()
        col_names = [r[1] for r in res]
        if "role_type" not in col_names and len(col_names) > 0:
            db.execute(text("ALTER TABLE employees ADD COLUMN role_type VARCHAR DEFAULT 'General'"))
            db.commit()
            print("[+] Added role_type column to employees table.")
    except Exception as e:
        print(f"[!] Warning in ensure_employee_role_column: {e}")


def ensure_action_requests_columns(db):

    """Ensure multi-level approval and AI classification columns exist on action_requests table in SQLite."""
    try:
        from sqlalchemy import text
        res = db.execute(text("PRAGMA table_info(action_requests)")).fetchall()
        col_names = [r[1] for r in res]
        if not col_names:
            return

        migrations = [
            ("required_approvals", "INTEGER DEFAULT 1"),
            ("current_approvals", "INTEGER DEFAULT 0"),
            ("approval_chain_json", "TEXT DEFAULT '[]'"),
            ("policy_tier", "VARCHAR DEFAULT 'STANDARD'"),
            ("file_classification", "VARCHAR DEFAULT 'INTERNAL'"),
            ("classification_confidence", "FLOAT DEFAULT 0.85"),
            ("classification_reason", "VARCHAR"),
            ("calculated_risk_score", "INTEGER DEFAULT 0"),
            ("calculated_risk_level", "VARCHAR DEFAULT 'LOW'"),
            ("risk_explanation_json", "TEXT DEFAULT '[]'"),
        ]

        for col, col_def in migrations:
            if col not in col_names:
                try:
                    db.execute(text(f"ALTER TABLE action_requests ADD COLUMN {col} {col_def}"))
                    db.commit()
                    print(f"[+] Added '{col}' column to action_requests table.")
                except Exception:
                    pass
    except Exception as e:
        print(f"[!] Warning in ensure_action_requests_columns: {e}")


def ensure_sensitive_keywords(db):

    """Ensure default company-sensitive keywords exist in database."""
    from backend.models.database import SensitiveKeyword
    from ai.sensitive_scanner import DEFAULT_SENSITIVE_KEYWORDS
    try:
        if db.query(SensitiveKeyword).first() is None:
            for item in DEFAULT_SENSITIVE_KEYWORDS:
                db.add(SensitiveKeyword(
                    keyword=item["keyword"],
                    category=item["category"],
                    risk_weight=item["risk_weight"],
                    is_active=True
                ))
            db.commit()
            print("[+] Seeded default sensitive asset keywords.")
    except Exception as e:
        print(f"[!] Warning in ensure_sensitive_keywords: {e}")

def init_db():
    print("Initializing SQLite database...")
    Base.metadata.create_all(bind=engine)
    print("Tables created successfully.")

    # THREATVISTA_SEED_DEMO=0 (or `reset_db.py --empty`) seeds only the role
    # accounts + system config — no mock employees/devices/events — so the SOC
    # shows *only* the employees that self-register and their real telemetry.
    seed_demo = os.environ.get("THREATVISTA_SEED_DEMO", "1").strip().lower() not in ("0", "false", "no")

    db = SessionLocal()
    try:
        # Idempotency: always ensure config, role_type column, sensitive keywords, valid admin hash, and demo roles exist.
        ensure_system_config(db)
        ensure_employee_role_column(db)
        ensure_action_requests_columns(db)
        ensure_sensitive_keywords(db)
        ensure_admin(db)
        ensure_admin_hash(db)
        ensure_analyst(db)
        ensure_auditor(db)


        # The SeedState marker stops an empty seed from being re-populated with
        # demo data on a later init_db() call.
        state = db.query(SeedState).first()
        if state is not None:
            print(f"Database already seeded (mode='{state.mode}'). Skipping seeding.")
            return
        # Legacy DBs seeded before SeedState existed: no marker, but employees exist.
        if db.query(Employee).first() is not None:
            db.add(SeedState(mode="demo"))
            db.commit()
            print("Database already contains data. Skipping seeding.")
            return

        if not seed_demo:
            db.add(SeedState(mode="empty"))
            db.commit()
            print("Empty-seed mode: no mock employees/devices/events. Only real registered data will show.")
            return

        print("Seeding database with initial mock data...")

        # 1. Role accounts (admin/analyst/auditor) are ensured above via
        #    ensure_admin / ensure_analyst / ensure_auditor.

        # 2. Employees
        rahul = Employee(
            name="Rahul Sharma",
            email="rahul.sharma@threatvista.com",
            department="Engineering",
            role_type="Developer",
            photo_url="/assets/avatars/rahul.jpg",
            risk_score=92,
            status="High Risk"
        )
        amit = Employee(
            name="Amit Verma",
            email="amit.verma@threatvista.com",
            department="Sales",
            role_type="Finance",
            photo_url="/assets/avatars/amit.jpg",
            risk_score=63,
            status="Suspicious"
        )
        priya = Employee(
            name="Priya Patel",
            email="priya.patel@threatvista.com",
            department="Human Resources",
            role_type="HR",
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

        # 3b. Endpoint Devices (seeded so the dashboard shows online endpoints)
        now_dt = datetime.utcnow()
        db.add_all([
            Device(
                employee_id=rahul.id,
                device_id="DEV-RHL-0001",
                hostname="RHLAPTOP01",
                os_version="Windows 11 Pro",
                os_build="26100",
                cpu_model="Intel Core i7-12700H",
                cpu_cores=14,
                ram_gb=32.0,
                disk_total_gb=512.0,
                disk_free_gb=187.4,
                ip_address="192.168.1.42",
                agent_version="1.0.0",
                status="online",
                last_seen_at=now_dt,
                first_seen_at=now_dt,
            ),
            Device(
                employee_id=amit.id,
                device_id="DEV-AMT-0002",
                hostname="AMT-PC02",
                os_version="Windows 11 Home",
                os_build="22631",
                cpu_model="AMD Ryzen 5 5600X",
                cpu_cores=6,
                ram_gb=16.0,
                disk_total_gb=256.0,
                disk_free_gb=62.8,
                ip_address="192.168.1.57",
                agent_version="1.0.0",
                status="online",
                last_seen_at=now_dt,
                first_seen_at=now_dt,
            ),
            Device(
                employee_id=priya.id,
                device_id="DEV-PRI-0003",
                hostname="PRIYA-HP3",
                os_version="Windows 11 Home",
                os_build="22631",
                cpu_model="Intel Core i5-1240P",
                cpu_cores=12,
                ram_gb=16.0,
                disk_total_gb=512.0,
                disk_free_gb=304.2,
                ip_address="192.168.1.63",
                agent_version="1.0.0",
                status="online",
                last_seen_at=now_dt,
                first_seen_at=now_dt,
            ),
        ])

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
            ),
            Event(
                employee_id=amit.id,
                event_type="file_copy",
                filename="sales_pipeline.xlsx",
                extension=".xlsx",
                size="3.8MB",
                folder="Sales",
                details="Copied 12 files to USB during out-of-hours session",
                timestamp=now - timedelta(hours=17)
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

        db.add(SeedState(mode="demo"))
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
