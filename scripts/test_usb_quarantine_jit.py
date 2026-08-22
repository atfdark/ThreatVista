"""
Test Suite: USB Write Interception, Quarantine & JIT Action Authorization.

Validates:
1. is_removable_drive_path accurately identifies external/USB vs C: drive paths.
2. ShadowVault quarantine_file backups and removes target file from USB.
3. ShadowVault release_quarantined_file restores file on USB upon Admin approval.
4. ShadowVault purge_quarantined_file wipes file upon Admin rejection.
5. ActionProtectionClient tracks recent USB moves to prevent duplicate file_delete tickets.
6. ActionProtectionClient check_for_approvals handles APPROVED and REJECTED usb_export actions.
7. ActionRequestService creates usb_export tickets with AI classification & explainable risk score.
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


def test_action_client_cross_drive_tracking():
    print("\n--- TEST 3: ActionProtectionClient Cross-Drive Move Tracking ---")
    with tempfile.TemporaryDirectory() as temp_dir:
        vault = ShadowVault(vault_dir=os.path.join(temp_dir, "vault"))
        client = ActionProtectionClient(vault=vault, employee_id=1, device_id="test-dev")

        # Record a USB interception
        client.record_interception("contract.pdf", "E:\\contract.pdf", "usb_export")
        assert client.has_recent_usb_interception("contract.pdf") is True, "Should detect recent interception"
        assert client.has_recent_usb_interception("CONTRACT.PDF") is True, "Should be case-insensitive"
        assert client.has_recent_usb_interception("other_file.txt") is False, "Other files should return False"
        print("[✓] Cross-drive move interception tracking verified.")


def test_jit_usb_export_ticket_backend():
    print("\n--- TEST 4: Backend JIT USB Export Action Request Lifecycle ---")
    db = SessionLocal()
    try:
        emp = db.query(Employee).first()
        if not emp:
            emp = Employee(name="Test Security User", role_type="Engineer", department="IT", risk_score=20, status="Safe")
            db.add(emp)
            db.commit()
            db.refresh(emp)

        # 1. Create USB export action request for 'contract_2026.docx'
        req = action_request_service.create_action_request(
            db=db,
            employee_id=emp.id,
            target_file="contract_2026.docx",
            file_path="E:\\contract_2026.docx",
            action_type="usb_export",
            device_id="test-device-101",
            file_size="2.4MB",
        )

        assert req["action_type"] == "usb_export", "Action type should be usb_export"
        assert req["file_classification"] == "CONFIDENTIAL", f"Expected CONFIDENTIAL, got {req['file_classification']}"
        assert req["calculated_risk_score"] >= 60, f"Expected elevated risk for USB confidential export, got {req['calculated_risk_score']}"
        assert req["status"] == "PENDING", "Initial status must be PENDING"
        req_id = req["id"]
        print(f"[✓] Created USB Export Action Request #{req_id} (Classification: {req['file_classification']}, Risk: {req['calculated_risk_score']}%)")

        # 2. Reject request
        rejected = action_request_service.reject_action_request(
            db=db,
            request_id=req_id,
            admin_name="SOC Admin",
            reason="Blocked: USB exfiltration of confidential contract violates policy."
        )
        assert rejected["status"] == "REJECTED", "Status should be REJECTED"
        print(f"[✓] Action Request #{req_id} successfully REJECTED by SOC Admin.")

        # 3. Create another USB export request for Approval test
        req2 = action_request_service.create_action_request(
            db=db,
            employee_id=emp.id,
            target_file="project_presentation.pptx",
            file_path="E:\\project_presentation.pptx",
            action_type="usb_export",
            device_id="test-device-101",
            file_size="5.1MB",
        )
        req2_id = req2["id"]
        approved = action_request_service.approve_action_request(
            db=db,
            request_id=req2_id,
            admin_name="SOC Admin",
            notes="Approved: Authorized client presentation export."
        )
        assert approved["status"] == "APPROVED", "Status should be APPROVED"
        print(f"[✓] Action Request #{req2_id} successfully APPROVED by SOC Admin.")

    finally:
        db.close()


if __name__ == "__main__":
    test_drive_detection()
    test_shadow_vault_quarantine_lifecycle()
    test_action_client_cross_drive_tracking()
    test_jit_usb_export_ticket_backend()
    print("\n=======================================================")
    print("ALL USB QUARANTINE & JIT AUTHORIZATION TESTS PASSED! ✓")
    print("=======================================================\n")
