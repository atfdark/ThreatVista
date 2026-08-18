import os
import sys
import time
from datetime import datetime

# Add root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ai.features import engineer_features
from ai.risk import RiskEngine
from ai.role_config import get_role_config, get_supported_roles, get_all_role_baselines
from ai.sensitive_scanner import SensitiveAssetScanner
from ai.pipeline import AIPipeline

def test_role_intelligence():
    print("=== Testing Role-Based Risk Intelligence ===")
    pipeline = AIPipeline()
    supported_roles = get_supported_roles()
    print(f"Supported roles ({len(supported_roles)}): {', '.join(supported_roles)}")
    assert len(supported_roles) == 9, "Expected 9 supported roles"

    now_iso = datetime.utcnow().isoformat()

    # Scenario 1: Developer creates 200 files
    dev_events = [
        {"id": i, "event_type": "file_create", "timestamp": now_iso, "filename": f"build_{i}.js", "folder": "C:/dev/src"}
        for i in range(200)
    ]
    dev_res = pipeline.run(dev_events, employee_id=1, role_type="Developer")
    dev_score = dev_res["risk"]["score"]
    dev_reasons = dev_res["risk"]["reasons"]
    print(f"Developer 200 files risk: {dev_score}% | Reasons: {dev_reasons}")
    assert any("Developer" in r for r in dev_reasons), "Expected Developer reasoning in risk explanation"

    # Scenario 2: HR creates 200 files
    hr_events = [
        {"id": i, "event_type": "file_create", "timestamp": now_iso, "filename": f"doc_{i}.pdf", "folder": "C:/hr"}
        for i in range(200)
    ]
    hr_res = pipeline.run(hr_events, employee_id=2, role_type="HR")
    hr_score = hr_res["risk"]["score"]
    hr_reasons = hr_res["risk"]["reasons"]
    print(f"HR 200 files risk: {hr_score}% | Reasons: {hr_reasons}")
    assert hr_score > dev_score, f"HR score ({hr_score}) should be higher than Developer score ({dev_score}) for mass file operations"
    assert any("HR" in r and "unusual" in r for r in hr_reasons), "Expected HR mass file creation warning"

    # Scenario 3: Finance copies source_code.zip
    finance_events = [
        {"id": 1, "event_type": "file_copy", "timestamp": now_iso, "filename": "source_code.zip", "extension": ".zip", "folder": "C:/finance"}
    ]
    finance_res = pipeline.run(finance_events, employee_id=3, role_type="Finance")
    fin_score = finance_res["risk"]["score"]
    fin_reasons = finance_res["risk"]["reasons"]
    print(f"Finance copies source_code.zip risk: {fin_score}% | Reasons: {fin_reasons}")
    assert fin_score >= 50, f"Expected Finance copying source_code.zip to produce >= 50 risk, got {fin_score}"

    # Scenario 4: Developer copies source_code.zip
    dev_code_events = [
        {"id": 1, "event_type": "file_copy", "timestamp": now_iso, "filename": "source_code.zip", "extension": ".zip", "folder": "C:/repo"}
    ]
    dev_code_res = pipeline.run(dev_code_events, employee_id=1, role_type="Developer")
    dev_code_score = dev_code_res["risk"]["score"]
    print(f"Developer copies source_code.zip risk: {dev_code_score}%")
    assert dev_code_score < fin_score, f"Developer risk ({dev_code_score}) should be substantially lower than Finance ({fin_score})"

    print("✓ Role-Based Risk Intelligence tests passed!\n")

def test_sensitive_asset_detection():
    print("=== Testing Sensitive Company Asset Detection ===")
    
    # 1. Single match: salary.xlsx (+10)
    m1 = SensitiveAssetScanner.match_file("salary.xlsx")
    print(f"salary.xlsx -> is_sensitive: {m1['is_sensitive']}, matched: {m1['matched_keywords']}, risk: +{m1['risk_added']}")
    assert m1["is_sensitive"] is True
    assert "salary" in m1["matched_keywords"]
    assert m1["risk_added"] == 10

    # 2. Case-insensitivity: SALARY.XLSX, Salary.xlsx
    m_case1 = SensitiveAssetScanner.match_file("SALARY.XLSX")
    m_case2 = SensitiveAssetScanner.match_file("Salary_Report_2026.xlsx")
    assert m_case1["is_sensitive"] and "salary" in m_case1["matched_keywords"]
    assert m_case2["is_sensitive"] and "salary" in m_case2["matched_keywords"]

    # 3. Partial & Group match: employee_database.csv (employee + database = 2 matches -> +20)
    m2 = SensitiveAssetScanner.match_file("employee_database.csv")
    print(f"employee_database.csv -> matched: {m2['matched_keywords']}, risk: +{m2['risk_added']}")
    assert len(m2["matched_keywords"]) >= 2
    assert m2["risk_added"] >= 20

    # 4. Sensitive ZIP match: project_alpha_salary_backup.zip (sensitive zip + keywords = +60 risk)
    m3 = SensitiveAssetScanner.match_file("project_alpha_salary_backup.zip", extension=".zip")
    print(f"project_alpha_salary_backup.zip -> is_sensitive_zip: {m3['is_sensitive_zip']}, matched: {m3['matched_keywords']}, risk: +{m3['risk_added']}")
    assert m3["is_sensitive_zip"] is True
    assert m3["risk_added"] >= 40
    assert "salary" in m3["matched_keywords"] or "project_alpha" in m3["matched_keywords"]

    # 5. Full Pipeline Evaluation with Sensitive Asset Detection
    pipeline = AIPipeline()
    now_iso = datetime.utcnow().isoformat()
    critical_events = [
        {"id": 1, "event_type": "usb_insert", "timestamp": now_iso, "usb_status": "SanDisk USB"},
        {"id": 2, "event_type": "file_copy", "timestamp": now_iso, "filename": "project_alpha_salary_backup.zip", "extension": ".zip", "folder": "E:/backup"}
    ]
    res = pipeline.run(critical_events, employee_id=4, role_type="General")
    print(f"Pipeline Result for project_alpha_salary_backup.zip on USB -> Risk: {res['risk']['score']}%, Status: {res['risk']['status']}")
    print(f"Explanation Reasons: {res['risk']['reasons']}")
    assert res['risk']['status'] in ("Critical", "High"), f"Expected High or Critical, got {res['risk']['status']}"
    assert any("Sensitive asset movement" in r or "salary" in r for r in res['risk']['reasons'])

    # 6. Performance Test with 1,000+ Keywords
    print("\nTesting keyword scanner performance with 1,000+ keywords...")
    mock_keywords = [
        {"keyword": f"confidential_asset_{i}", "category": "Intellectual Property", "risk_weight": 10}
        for i in range(1000)
    ]
    mock_keywords.append({"keyword": "project_alpha", "category": "Strategic", "risk_weight": 10})
    SensitiveAssetScanner._cached_keywords = mock_keywords
    SensitiveAssetScanner._cache_time = time.time() + 1000

    start = time.perf_counter()
    for _ in range(100):
        SensitiveAssetScanner.match_file("project_alpha_source_code.zip", extension=".zip")
    elapsed_ms = (time.perf_counter() - start) * 1000 / 100
    print(f"Average scan time per file across 1,000+ keywords: {elapsed_ms:.3f} ms")
    assert elapsed_ms < 5.0, "Scan must be fast (< 5ms)"

    print("✓ Sensitive Company Asset Detection tests passed!\n")

if __name__ == "__main__":
    test_role_intelligence()
    test_sensitive_asset_detection()
    print("ALL TESTS PASSED SUCCESSFULLY! 🚀")
