"""
Comprehensive Verification Suite for ThreatVista Priority 1 Innovations:
1. AI File Sensitivity Classification
2. Explainable Dynamic Risk Scoring Engine
3. Automatic Approval Request Expiration
"""
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database.connection import SessionLocal
from backend.models import database as models
from backend.services.file_classifier import classify_file, RESTRICTED, CONFIDENTIAL, INTERNAL, PUBLIC
from backend.services.jit_risk_engine import calculate_risk_score
from backend.services.action_request_service import (
    create_action_request,
    approve_action_request,
    reject_action_request,
    get_pending_count,
    list_action_requests,
)
from backend.services.request_expiry_service import expire_stale_requests


def test_file_classification():
    print("\n--- FEATURE 1: AI File Sensitivity Classification ---")
    test_cases = [
        ("salary.xlsx", CONFIDENTIAL),
        ("employees.csv", CONFIDENTIAL),
        ("bank_transactions.xlsx", RESTRICTED),
        ("source_code.zip", RESTRICTED),
        ("holiday_photo.jpg", PUBLIC),
        ("presentation.pptx", INTERNAL),
        ("passwords_vault.kdbx", RESTRICTED),
        ("marketing_banner.png", PUBLIC),
        ("q3_financial_ledger.xlsx", CONFIDENTIAL),
        ("project_architecture_spec.docx", INTERNAL),
    ]

    for filename, expected_category in test_cases:
        res = classify_file(file_path=f"C:\\Users\\Workspace\\{filename}", filename=filename)
        actual = res["classification"]
        confidence = res["confidence"]
        reason = res["reason"]
        assert actual == expected_category, f"Mismatch for '{filename}': expected {expected_category}, got {actual}"
        print(f" [✓] '{filename}' -> {actual} (Confidence: {int(confidence * 100)}%) | {reason}")

    print("[✓] All file classification test cases passed with 100% precision.")


def test_explainable_risk_scoring():
    print("\n--- FEATURE 2: Explainable Dynamic Risk Scoring Engine ---")
    db = SessionLocal()
    try:
        # Case A: Public photo deleted in work hours on C: drive -> LOW Risk
        res_low = calculate_risk_score(
            db=None,
            employee_id=1,
            action_type="file_delete",
            file_path="C:\\Users\\alokk\\Pictures\\holiday_photo.jpg",
            classification="PUBLIC",
            target_time=datetime(2026, 8, 19, 14, 0, 0),  # 2:00 PM Wednesday
        )
        assert res_low["risk_level"] in ("LOW", "MEDIUM"), f"Expected LOW/MED risk, got {res_low}"
        print(f" [✓] Case A (Public deletion): Score={res_low['risk_score']} Level={res_low['risk_level']} | Reasons={res_low['explanation']}")

        # Case B: Restricted password/bank file deleted from USB drive on weekend/night -> HIGH Risk
        res_high = calculate_risk_score(
            db=None,
            employee_id=1,
            action_type="file_delete",
            file_path="E:\\Vault\\bank_transactions.xlsx",
            classification="RESTRICTED",
            target_time=datetime(2026, 8, 23, 23, 30, 0),  # 11:30 PM Sunday
        )
        # Restricted (+40) + Delete (+20) + External Drive (+20) + After Hours (+15) = 95 -> HIGH
        assert res_high["risk_score"] >= 80, f"Expected high score >= 80, got {res_high['risk_score']}"
        assert res_high["risk_level"] == "HIGH", f"Expected HIGH, got {res_high['risk_level']}"
        assert "Restricted file" in res_high["explanation"]
        assert "Delete attempt" in res_high["explanation"]
        assert "External drive detected" in res_high["explanation"]
        assert "After-hours activity" in res_high["explanation"]
        print(f" [✓] Case B (Restricted USB Delete): Score={res_high['risk_score']} Level={res_high['risk_level']} | Reasons={res_high['explanation']}")

    finally:
        db.close()

    print("[✓] Dynamic explainable risk scoring engine verified.")


def test_automatic_request_expiration():
    print("\n--- FEATURE 3: Automatic Approval Request Expiration ---")
    db = SessionLocal()
    try:
        emp = db.query(models.Employee).first()
        if not emp:
            emp = models.Employee(
                name="Test Expiry User",
                email="expiry.test@threatvista.com",
                department="Engineering",
                role_type="Developer",
                risk_score=15,
                status="Normal",
            )
            db.add(emp)
            db.commit()
            db.refresh(emp)

        # 1. Create a request and artificially backdate its requested_at and expires_at
        req_data = create_action_request(
            db=db,
            employee_id=emp.id,
            target_file="old_contract_draft.docx",
            file_path="C:\\Users\\Workspace\\old_contract_draft.docx",
            action_type="file_delete",
        )
        req_id = req_data["id"]

        req_record = db.query(models.ActionRequest).filter(models.ActionRequest.id == req_id).first()
        req_record.requested_at = datetime.utcnow() - timedelta(minutes=6)
        req_record.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.commit()

        print(f" [✓] Backdated Action Request #{req_id} past 5-minute TTL.")

        # 2. Run expiration scanner
        expired_ids = expire_stale_requests(db)
        assert req_id in expired_ids, f"Request #{req_id} was not returned in expired_ids: {expired_ids}"

        # 3. Verify status in database
        db.refresh(req_record)
        assert req_record.status == "EXPIRED", f"Expected EXPIRED status, got {req_record.status}"
        assert req_record.resolved_by == "System Auto-Expiry"
        print(f" [✓] Action Request #{req_id} successfully auto-expired (Status: EXPIRED).")

        # 4. Verify cannot approve or reject expired request
        try:
            approve_action_request(db=db, request_id=req_id)
            assert False, "Should not allow approving an expired request"
        except ValueError as e:
            assert "expired" in str(e).lower()
            print(f" [✓] Attempting to approve expired request correctly rejected: '{e}'")

    finally:
        db.close()

    print("[✓] Automatic 5-minute request expiration lifecycle verified.")


def test_end_to_end_jit_flow():
    print("\n--- TEST 4: End-to-End JIT Ticket Lifecycle Integration ---")
    db = SessionLocal()
    try:
        emp = db.query(models.Employee).first()

        # Submit ticket for confidential payroll file
        req = create_action_request(
            db=db,
            employee_id=emp.id,
            target_file="salary_bonus_2026.xlsx",
            file_path="E:\\HR\\salary_bonus_2026.xlsx",
            action_type="file_delete",
        )
        req_id = req["id"]

        assert req["file_classification"] == "CONFIDENTIAL"
        assert req["calculated_risk_score"] >= 45
        assert len(req["risk_explanation"]) >= 2
        print(f" [✓] Ticket #{req_id} created with Sensitivity: {req['file_classification']} | Risk: {req['calculated_risk_score']}% ({req['calculated_risk_level']})")

        # Query pending list
        pending_list = list_action_requests(db, status="PENDING")
        assert any(r["id"] == req_id for r in pending_list)
        print(f" [✓] Ticket #{req_id} visible in SOC pending queue.")

        # Approve ticket
        approved = approve_action_request(db, req_id, admin_name="SecAdmin", notes="Authorized audit deletion")
        assert approved["status"] == "APPROVED"
        assert approved["resolved_by"] == "SecAdmin"
        print(f" [✓] Ticket #{req_id} approved with audit notes.")

    finally:
        db.close()


if __name__ == "__main__":
    test_file_classification()
    test_explainable_risk_scoring()
    test_automatic_request_expiration()
    test_end_to_end_jit_flow()
    print("\n=======================================================")
    print("ALL PRIORITY 1 INNOVATIONS TESTED & VALIDATED 100%!")
    print("=======================================================\n")
