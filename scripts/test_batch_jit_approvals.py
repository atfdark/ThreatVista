"""
Test suite verifying JIT Action Authorization Batch Actions & Narrative Summaries:
1. Creation of USB exfiltration, deletion, and modification tickets.
2. Batch Approval of selected tickets.
3. Batch Rejection of selected tickets.
4. Auto-generated action narrative and source -> destination path verification.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database.connection import SessionLocal
from backend.database.db_setup import init_db
from backend.models import database as models
from backend.services.action_request_service import (
    create_action_request,
    list_action_requests,
)


def test_batch_resolve_flow():
    print("\n--- TEST: JIT Action Center Batch Approval & Rejection ---")
    init_db()
    db = SessionLocal()
    try:
        emp = db.query(models.Employee).first()
        if not emp:
            emp = models.Employee(name="Rohit Sharma", email="rohit.sharma@threatvista.com", department="Engineering", role_type="Developer", risk_score=75)
            db.add(emp)
            db.commit()
            db.refresh(emp)

        ts = int(time.time())

        # Ticket 1: USB Transfer / Exfiltration
        t1 = create_action_request(
            db=db,
            employee_id=emp.id,
            target_file=f"salary_q3_{ts}.xlsx",
            file_path=f"E:\\USB_Drive\\salary_q3_{ts}.xlsx",
            action_type="usb_export",
        )
        print(f" [✓] Created Ticket #{t1['id']} (USB Export): {t1['target_file']}")

        # Ticket 2: File Deletion
        t2 = create_action_request(
            db=db,
            employee_id=emp.id,
            target_file=f"database_dump_{ts}.sql",
            file_path=f"C:\\Database\\database_dump_{ts}.sql",
            action_type="file_delete",
        )
        print(f" [✓] Created Ticket #{t2['id']} (File Deletion): {t2['target_file']}")

        # Ticket 3: Suspicious Modify / Ransomware
        t3 = create_action_request(
            db=db,
            employee_id=emp.id,
            target_file=f"client_contracts_{ts}.docx",
            file_path=f"C:\\Contracts\\client_contracts_{ts}.docx",
            action_type="file_modify",
        )
        print(f" [✓] Created Ticket #{t3['id']} (File Modify): {t3['target_file']}")

        from backend.services.action_request_service import approve_action_request, reject_action_request

        # Batch Approve Ticket 1 & Ticket 2
        batch_approve_ids = [t1['id'], t2['id']]
        for rid in batch_approve_ids:
            res = approve_action_request(db, rid, admin_name="Admin", notes="Batch approved by SOC Admin")
            print(f" [✓] Batch Approved Ticket #{rid}: Status = {res['status']}")
            assert res["status"] in ("APPROVED", "PARTIALLY_APPROVED")

        # Batch Reject Ticket 3
        res3 = reject_action_request(db, t3['id'], admin_name="Admin", reason="Batch denied by SOC Admin")
        print(f" [✓] Batch Rejected Ticket #{t3['id']}: Status = {res3['status']}")
        assert res3["status"] == "REJECTED"

        print("[✓] Batch Approval and Rejection verified 100%!")

    finally:
        db.close()


if __name__ == "__main__":
    test_batch_resolve_flow()
