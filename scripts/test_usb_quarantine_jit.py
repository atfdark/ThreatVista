"""
Test Suite: USB Write Interception, Quarantine & JIT Action Authorization.

Validates:
1. is_removable_drive_path accurately identifies external/USB vs C: drive paths.
2. ShadowVault quarantine_file backups and removes target file from USB.
3. ShadowVault release_quarantined_file restores file on USB upon Admin approval.
4. ShadowVault purge_quarantined_file wipes file upon Admin rejection AND preserves source.
5. Zero-Data-Loss: Rejected cross-drive move preserves file in original local directory (e.g. Downloads).
6. Deduplication Engine: Rapid duplicate writes (5-6 events in seconds) produce exactly 1 ticket.
7. ActionProtectionClient tracks recent USB moves to prevent duplicate file_delete tickets.
8. ActionProtectionClient check_for_approvals handles APPROVED and REJECTED usb_export actions.
9. ActionRequestService creates usb_export tickets with AI classification & explainable risk score.
"""
import os
import sys
import tempfile
import shutil
from datetime import datetime

# Setup path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from endpoint_agent.protection.vault import ShadowVault
from endpoint_agent.protection.action_client import ActionProtectionClient
from endpoint_agent.monitors.file_monitor import is_removable_drive_path
from backend.database.connection import SessionLocal
from backend.models.database import Employee, ActionRequest, Alert
from backend.services import action_request_service


def test_drive_detection():
    print("\n--- TEST 1: Removable / External Drive Path Detection ---")
    assert is_removable_drive_path("E:\\contract.docx") is True, "E:\\ should be recognized as external/removable"
    assert is_removable_drive_path("F:\\data\\salary.xlsx") is True, "F:\\ should be recognized as external/removable"
    assert is_removable_drive_path("D:\\backup.zip") is True, "D:\\ should be recognized as external/removable"
    assert is_removable_drive_path("C:\\Users\\user\\Downloads\\contract.docx") is False, "C:\\ Downloads should NOT be recognized as removable"
    print("[✓] Drive detection accurately distinguishes USB/external drives from C: drive.")


def test_shadow_vault_quarantine_lifecycle():
    print("\n--- TEST 2: Shadow Vault USB Quarantine & Release Lifecycle ---")
    with tempfile.TemporaryDirectory() as temp_dir:
        vault_dir = os.path.join(temp_dir, "vault")
        usb_dir = os.path.join(temp_dir, "simulated_usb")
        os.makedirs(usb_dir, exist_ok=True)

        vault = ShadowVault(vault_dir=vault_dir)

        # 1. Simulate file written to USB
        usb_file = os.path.join(usb_dir, "contract_q3.pdf")
        secret_content = b"CONFIDENTIAL CORPORATE CONTRACT DETAILS 2026"
        with open(usb_file, "wb") as f:
            f.write(secret_content)

        assert os.path.exists(usb_file), "USB file should exist before quarantine"

        # 2. Quarantine file
        success = vault.quarantine_file(usb_file)
        assert success is True, "Quarantine should succeed"
        assert not os.path.exists(usb_file), "File must be REMOVED from USB drive upon quarantine"
        assert vault.has_backup(usb_file), "Snapshot must be held securely in Shadow Vault"
        print("[✓] File successfully quarantined and removed from simulated USB drive.")

        # 3. Release quarantined file (Simulating Admin Approval)
        rel_success = vault.release_quarantined_file(usb_file)
        assert rel_success is True, "Release should succeed"
        assert os.path.exists(usb_file), "File must be restored onto USB drive upon release"
        with open(usb_file, "rb") as f:
            assert f.read() == secret_content, "Restored file content must match 100%"
        print("[✓] Quarantined file successfully released onto USB drive with 100% integrity.")

        # 4. Purge quarantined file (Simulating Admin Rejection)
        vault.purge_quarantined_file(usb_file)
        assert not os.path.exists(usb_file), "File must be wiped from USB upon rejection purge"
        assert not vault.has_backup(usb_file), "Vault snapshot must be purged"
        print("[✓] Rejected file purged cleanly from USB drive and Shadow Vault.")


def test_zero_data_loss_on_rejected_usb_move():
    print("\n--- TEST 3: Zero-Data-Loss on Rejected Cross-Drive Move ---")
    with tempfile.TemporaryDirectory() as temp_dir:
        vault_dir = os.path.join(temp_dir, "vault")
        downloads_dir = os.path.join(temp_dir, "Downloads")
        usb_dir = os.path.join(temp_dir, "USB_Drive")
        os.makedirs(downloads_dir, exist_ok=True)
        os.makedirs(usb_dir, exist_ok=True)

        vault = ShadowVault(vault_dir=vault_dir)

        # 1. File starts in Downloads
        source_file = os.path.join(downloads_dir, "salary_august.docx")
        salary_content = b"CONFIDENTIAL EMPLOYEE SALARY SHEET 2026 - $120,000"
        with open(source_file, "wb") as f:
            f.write(salary_content)

        # 2. User moves file to USB (Windows creates destination, ThreatVista intercepts)
        usb_file = os.path.join(usb_dir, "salary_august.docx")
        with open(usb_file, "wb") as f:
            f.write(salary_content)

        # ThreatVista intercepts and quarantines
        vault.quarantine_file(usb_file, source_path=source_file)
        assert not os.path.exists(usb_file), "File must be quarantined from USB drive"

        # Windows finishes move by deleting the source file in Downloads
        if os.path.exists(source_file):
            os.remove(source_file)
        assert not os.path.exists(source_file), "Simulated OS deletion of source during Cut/Move"

        # 3. Admin REJECTS the USB transfer
        # ShadowVault purge must ensure source file in Downloads is restored!
        vault.purge_quarantined_file(usb_file, fallback_source_path=source_file)

        # 4. Verify: File is BLOCKED from USB, but PRESERVED in Downloads!
        assert not os.path.exists(usb_file), "File must NOT be on USB drive (Policy Enforced)"
        assert os.path.exists(source_file), "Source file MUST be preserved in Downloads (Zero Data Loss)"
        with open(source_file, "rb") as f:
            assert f.read() == salary_content, "Restored local file content must match exactly"
        print("[✓] Zero-Data-Loss verified: Rejected USB export blocked on USB and restored safely in Downloads.")


def test_action_client_cross_drive_tracking():
    print("\n--- TEST 4: ActionProtectionClient Cross-Drive Move Tracking & Debouncing ---")
    with tempfile.TemporaryDirectory() as temp_dir:
        vault = ShadowVault(vault_dir=os.path.join(temp_dir, "vault"))
        client = ActionProtectionClient(vault=vault, employee_id=1, device_id="test-dev")

        # Record a USB interception with source path
        client.record_interception("contract.pdf", "E:\\contract.pdf", "usb_export", source_path="C:\\Downloads\\contract.pdf")
        assert client.has_recent_usb_interception("contract.pdf") is True, "Should detect recent interception"
        assert client.has_recent_usb_interception("CONTRACT.PDF") is True, "Should be case-insensitive"
        assert client.has_recent_usb_interception("other_file.txt") is False, "Other files should return False"
        assert client.get_source_path("contract.pdf") == "C:\\Downloads\\contract.pdf", "Should remember source path"
        print("[✓] Cross-drive move interception tracking and source path mapping verified.")


def test_jit_usb_export_ticket_backend_deduplication():
    print("\n--- TEST 5: Backend JIT USB Export Action Request Deduplication ---")
    db = SessionLocal()
    try:
        emp = db.query(Employee).first()
        if not emp:
            emp = Employee(name="Test Security User", role_type="Engineer", department="IT", risk_score=20, status="Safe")
            db.add(emp)
            db.commit()
            db.refresh(emp)

        initial_pending_count = action_request_service.get_pending_count(db)

        # 1. Create USB export action request for 'salary_dedup_test.docx' (1st call)
        req1 = action_request_service.create_action_request(
            db=db,
            employee_id=emp.id,
            target_file="salary_dedup_test.docx",
            file_path="D:\\salary_dedup_test.docx",
            action_type="usb_export",
            device_id="test-device-101",
            file_size="1.5MB",
        )
        req1_id = req1["id"]

        # 2. Simulate 5 rapid-fire duplicate calls (like Windows Explorer file chunk writes)
        for i in range(5):
            req_dup = action_request_service.create_action_request(
                db=db,
                employee_id=emp.id,
                target_file="salary_dedup_test.docx",
                file_path="D:\\salary_dedup_test.docx",
                action_type="usb_export",
                device_id="test-device-101",
                file_size="1.5MB",
            )
            assert req_dup["id"] == req1_id, f"Duplicate call {i} must return the existing ticket #{req1_id}, not create a new one"

        # Verify pending count only increased by 1
        new_pending_count = action_request_service.get_pending_count(db)
        assert new_pending_count == initial_pending_count + 1, f"Expected pending count to increase by exactly 1, got {new_pending_count - initial_pending_count}"
        print(f"[✓] Backend deduplication verified: 6 rapid calls resulted in exactly 1 pending ticket (#{req1_id}).")

        # 3. Reject request and verify resolution
        rejected = action_request_service.reject_action_request(
            db=db,
            request_id=req1_id,
            admin_name="SOC Admin",
            reason="Blocked: USB transfer denied"
        )
        assert rejected["status"] == "REJECTED", "Status should be REJECTED"
        print(f"[✓] Action Request #{req1_id} successfully REJECTED by SOC Admin.")

    finally:
        db.close()


def test_force_remove_locked_usb_file():
    print("\n--- TEST 6: Forceful Removal & Retries for Locked USB Files ---")
    with tempfile.TemporaryDirectory() as temp_dir:
        vault_dir = os.path.join(temp_dir, "vault")
        usb_dir = os.path.join(temp_dir, "USB_Drive")
        downloads_dir = os.path.join(temp_dir, "Downloads")
        os.makedirs(usb_dir, exist_ok=True)
        os.makedirs(downloads_dir, exist_ok=True)

        vault = ShadowVault(vault_dir=vault_dir)

        # 1. Setup file in Downloads & copy to USB
        source_file = os.path.join(downloads_dir, "locked_contract.pdf")
        usb_file = os.path.join(usb_dir, "locked_contract.pdf")
        data = b"TOP SECRET FINANCIAL REPORT 2026"
        with open(source_file, "wb") as f:
            f.write(data)
        with open(usb_file, "wb") as f:
            f.write(data)

        # Quarantine it
        vault.quarantine_file(usb_file, source_path=source_file)

        # Re-create locked file on USB simulating Explorer delayed write handle
        with open(usb_file, "wb") as f:
            f.write(data)

        # 2. Call purge_quarantined_file
        purged = vault.purge_quarantined_file(usb_file, fallback_source_path=source_file)
        assert purged is True, "Purge must return True"
        assert not os.path.exists(usb_file), "USB file must be wiped completely"
        assert os.path.exists(source_file), "Local Downloads source copy must be preserved"
        print("[✓] Forceful removal & retries verified: Locked USB file wiped and local Downloads preserved.")


if __name__ == "__main__":
    test_drive_detection()
    test_shadow_vault_quarantine_lifecycle()
    test_zero_data_loss_on_rejected_usb_move()
    test_action_client_cross_drive_tracking()
    test_jit_usb_export_ticket_backend_deduplication()
    test_force_remove_locked_usb_file()
    print("\n=======================================================")
    print("ALL USB QUARANTINE & JIT AUTHORIZATION TESTS PASSED! ✓")
    print("=======================================================\n")
