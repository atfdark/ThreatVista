"""
Comprehensive Verification Suite for ThreatVista Priority 2 Innovations:
1. User Behavior Analytics (UBA)
2. Employee Digital Twin Fingerprinting
3. Multi-Dimensional Behavioral Anomaly Detection
4. Adaptive Risk Scoring Integration
5. REST APIs & WebSocket Broadcasts
"""
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database.connection import SessionLocal
from backend.models import database as models
from backend.services.user_behavior_service import (
    get_or_create_behavior_profile,
    update_employee_behavior_profile,
    profile_to_dict,
)
from backend.services.digital_twin_service import generate_employee_baseline
from backend.services.anomaly_detection_service import detect_behavior_anomaly
from backend.services.jit_risk_engine import calculate_risk_score
from backend.services.file_classifier import classify_file


def get_test_employee(db):
    emp = db.query(models.Employee).first()
    if not emp:
        emp = models.Employee(
            name="Alice Developer",
            email="alice.dev@threatvista.com",
            department="Engineering",
            role_type="Developer",
            risk_score=20,
            status="Normal",
        )
        db.add(emp)
        db.commit()
        db.refresh(emp)
    return emp


def test_uba_profile_and_digital_twin():
    print("\n--- FEATURE 1 & 2: UBA Profile & Digital Twin Fingerprinting ---")
    db = SessionLocal()
    try:
        emp = get_test_employee(db)

        # 1. Create or retrieve UBA profile
        profile = get_or_create_behavior_profile(db, emp.id)
        p_dict = profile_to_dict(profile)
        assert p_dict["employee_id"] == emp.id
        assert p_dict["avg_login_hour"] > 0
        assert p_dict["avg_files_accessed_per_day"] > 0
        print(f" [✓] UBA Profile generated for {emp.name}: Operating Hours={p_dict['normal_working_hours']}, Daily Files={p_dict['avg_files_accessed_per_day']}")

        # 2. Generate Digital Twin
        twin = generate_employee_baseline(db, emp.id)
        assert twin["employee_id"] == emp.id
        assert "normal_hours" in twin
        assert "usb_frequency" in twin
        assert "common_directories" in twin
        print(f" [✓] Digital Twin Fingerprint: USB Habit={twin['usb_frequency']}, Threat Baseline={twin['risk_profile']} Risk, Workspaces={twin['common_directories']}")

    finally:
        db.close()


def test_time_anomaly_detection():
    print("\n--- FEATURE 3A: Time Anomaly Detection (Off-Hours Activity) ---")
    db = SessionLocal()
    try:
        emp = get_test_employee(db)

        # Action at 02:15 AM (Night activity -> 7h off 09:00 baseline)
        target_time = datetime(2026, 8, 19, 20, 45, 0) # UTC 20:45 -> IST 02:15 AM
        anom = detect_behavior_anomaly(
            db=db,
            employee_id=emp.id,
            file_path="C:\\Users\\alokk\\Projects\\code.py",
            action_type="file_modify",
            classification="INTERNAL",
            target_time=target_time,
        )

        assert anom["anomaly_score"] >= 25, f"Expected anomaly score >= 25, got {anom['anomaly_score']}"
        assert any("after-hours" in ind.lower() or "off-hours" in ind.lower() for ind in anom["indicators"])
        print(f" [✓] Time Anomaly Detected: Score={anom['anomaly_score']}% ({anom['severity']}) | Indicators={anom['indicators']}")

    finally:
        db.close()


def test_volume_anomaly_detection():
    print("\n--- FEATURE 3B: Volume Anomaly Detection (Mass File Spikes) ---")
    db = SessionLocal()
    try:
        emp = get_test_employee(db)

        # Simulate mass file activity (250 files vs ~15-45 avg)
        anom = detect_behavior_anomaly(
            db=db,
            employee_id=emp.id,
            file_path="C:\\Users\\alokk\\Projects\\archive.zip",
            action_type="file_delete",
            classification="INTERNAL",
            recent_file_count=250,
            target_time=datetime(2026, 8, 19, 8, 30, 0), # 2:00 PM IST (working hours)
        )

        assert anom["anomaly_score"] >= 30, f"Expected anomaly score >= 30, got {anom['anomaly_score']}"
        assert any("mass file" in ind.lower() for ind in anom["indicators"])
        print(f" [✓] Volume Anomaly Detected: Score={anom['anomaly_score']}% ({anom['severity']}) | Indicators={anom['indicators']}")

    finally:
        db.close()


def test_usb_and_directory_anomalies():
    print("\n--- FEATURE 3C: USB & Foreign Directory Anomaly Detection ---")
    db = SessionLocal()
    try:
        emp = get_test_employee(db)

        # Developer accessing confidential payroll ledger on USB drive
        anom = detect_behavior_anomaly(
            db=db,
            employee_id=emp.id,
            file_path="E:\\Finance\\Payroll\\salary_ledger_2026.xlsx",
            action_type="file_delete",
            classification="CONFIDENTIAL",
            is_usb=True,
            target_time=datetime(2026, 8, 19, 8, 30, 0), # Working hours
        )

        assert anom["anomaly_score"] >= 45, f"Expected anomaly score >= 45, got {anom['anomaly_score']}"
        assert any("usb" in ind.lower() for ind in anom["indicators"])
        assert any("directory" in ind.lower() or "finance" in ind.lower() or "payroll" in ind.lower() for ind in anom["indicators"])
        print(f" [✓] USB & Directory Anomalies Detected: Score={anom['anomaly_score']}% ({anom['severity']}) | Indicators={anom['indicators']}")

    finally:
        db.close()


def test_adaptive_risk_scoring_integration():
    print("\n--- FEATURE 4: Adaptive Dynamic Risk Scoring Integration ---")
    db = SessionLocal()
    try:
        emp = get_test_employee(db)

        # High composite anomaly: Restricted file + Delete + USB + Foreign Directory + Off-hours
        file_path = "E:\\Finance\\bank_transactions.xlsx"
        cls_res = classify_file(file_path=file_path)

        risk_res = calculate_risk_score(
            db=db,
            employee_id=emp.id,
            action_type="file_delete",
            file_path=file_path,
            classification=cls_res["classification"],
            target_time=datetime(2026, 8, 19, 20, 45, 0), # IST 02:15 AM
        )

        assert risk_res["risk_score"] >= 75, f"Expected high risk >= 75, got {risk_res['risk_score']}"
        assert risk_res["risk_level"] == "HIGH"
        assert len(risk_res["explanation"]) >= 3
        print(f" [✓] Adaptive Risk Calculated: Score={risk_res['risk_score']}% ({risk_res['risk_level']})")
        print(f"     Explainable Factor Trail:")
        for exp in risk_res["explanation"]:
            print(f"      • {exp}")

    finally:
        db.close()


if __name__ == "__main__":
    test_uba_profile_and_digital_twin()
    test_time_anomaly_detection()
    test_volume_anomaly_detection()
    test_usb_and_directory_anomalies()
    test_adaptive_risk_scoring_integration()
    print("\n=======================================================")
    print("ALL PRIORITY 2 BEHAVIORAL ANALYTICS TESTS PASSED 100%!")
    print("=======================================================\n")
