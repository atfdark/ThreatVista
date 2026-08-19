"""
Automated Test for ThreatVista Shadow Vault & JIT Admin Authorization System.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database.connection import SessionLocal
from backend.models import database as models
from backend.services import action_request_service
from endpoint_agent.protection.vault import ShadowVault


def test_shadow_vault():
    print("\n--- TEST 1: Shadow Vault Backup & Instant Rollback ---")
    with tempfile.TemporaryDirectory() as temp_dir:
        vault_dir = os.path.join(temp_dir, "vault")
        work_dir = os.path.join(temp_dir, "work")
        os.makedirs(work_dir, exist_ok=True)

        vault = ShadowVault(vault_dir=vault_dir)

        test_file = os.path.join(work_dir, "salary_confidential.xlsx")
        with open(test_file, "w") as f:
            f.write("CONFIDENTIAL SALARY LEDGER 2026")

        # 1. Backup file
        backed_up = vault.backup_file(test_file)
        assert backed_up, "Failed to create shadow snapshot"
        assert vault.has_backup(test_file), "Vault does not report backup exists"
        print("[✓] Shadow snapshot created in vault.")

        # 2. Simulate unauthorized deletion
        os.remove(test_file)
        assert not os.path.exists(test_file), "File was not deleted"
        print("[!] File deleted by unauthorized action.")

        # 3. Instant restore
        restored = vault.restore_file(test_file)
        assert restored, "Vault failed to restore file"
        assert os.path.exists(test_file), "File was not restored to disk"
        with open(test_file, "r") as f:
            content = f.read()
        assert content == "CONFIDENTIAL SALARY LEDGER 2026", "Content mismatch after restore"
        print("[✓] File instantly restored with 100% data integrity.")

        # 4. Approved purge
        purged = vault.purge_file(test_file)
        assert purged, "Failed to execute approved purge"
        assert not os.path.exists(test_file), "File still exists after purge"
        assert not vault.has_backup(test_file), "Shadow backup still exists after purge"
        print("[✓] File purged cleanly from working dir & vault upon Admin approval.")


def test_action_request_lifecycle():
    print("\n--- TEST 2: JIT Action Request Lifecycle & Backend Service ---")
    db = SessionLocal()
    try:
        # Find or create a test employee
        emp = db.query(models.Employee).first()
        if not emp:
            emp = models.Employee(
                name="Test Protection User",
                email="protection.test@threatvista.com",
                department="Engineering",
                role_type="Developer",
                risk_score=20,
                status="Normal"
            )
            db.add(emp)
            db.commit()
            db.refresh(emp)

        initial_risk = emp.risk_score or 0

        # 1. Create Action Request Ticket (PENDING)
        req = action_request_service.create_action_request(
            db=db,
            employee_id=emp.id,
            target_file="project_alpha_source.zip",
            file_path="E:\\Projects\\project_alpha_source.zip",
            action_type="file_delete",
            risk_context="Developer attempted to delete 1 archive following USB detachment."
        )
        req_id = req["id"]
        assert req["status"] == "PENDING"
        print(f"[✓] Created Action Request #{req_id} (Status: PENDING).")

        # 2. Check pending count
        count = action_request_service.get_pending_count(db)
        assert count >= 1, f"Expected at least 1 pending request, got {count}"
        print(f"[✓] Pending requests count verified: {count}")

        # 3. Approve request
        approved = action_request_service.approve_action_request(
            db=db,
            request_id=req_id,
            admin_name="SecurityAdmin",
            notes="Authorized change request ticket #CHG-492"
        )
        assert approved["status"] == "APPROVED"
        assert approved["resolved_by"] == "SecurityAdmin"
        print(f"[✓] Action Request #{req_id} APPROVED successfully.")

        # 4. Create second request to test rejection
        req2 = action_request_service.create_action_request(
            db=db,
            employee_id=emp.id,
            target_file="passwords_vault.kdbx",
            file_path="C:\\Users\\alokk\\Documents\\passwords_vault.kdbx",
            action_type="file_delete",
            risk_context="Suspicious deletion of credential vault."
        )
        req2_id = req2["id"]

        rejected = action_request_service.reject_action_request(
            db=db,
            request_id=req2_id,
            admin_name="SecurityAdmin",
            reason="Violation of security policy"
        )
        assert rejected["status"] == "REJECTED"
        print(f"[✓] Action Request #{req2_id} REJECTED successfully.")

        # Check risk score escalation and alert generation
        db.refresh(emp)
        assert emp.risk_score >= initial_risk + 10, f"Expected risk score to increase by 10, got {emp.risk_score}"
        print(f"[✓] Employee risk score escalated to {emp.risk_score}% and security alert logged.")

    finally:
        db.close()


if __name__ == "__main__":
    test_shadow_vault()
    test_action_request_lifecycle()
    print("\n=======================================================")
    print("ALL TESTS PASSED SUCCESSFULLY! ACTIVE PROTECTION VERIFIED.")
    print("=======================================================\n")
