import os
import sys
import uuid
import requests

BASE_URL = "http://127.0.0.1:8000/api"

def test_events_and_paths():
    print("=== Testing Real-time Event Stream & File Deletion Paths ===")
    
    unique_id = uuid.uuid4().hex[:6]
    emp_email = f"tester_{unique_id}@threatvista.com"
    
    # 1. Login as admin
    admin_res = requests.post(f"{BASE_URL}/auth/login", json={"username": "admin", "password": "admin123"})
    admin_token = admin_res.json()["access_token"]

    # Register test employee
    reg_res = requests.post(f"{BASE_URL}/auth/register", json={
        "username": emp_email,
        "password": "password123",
        "name": f"Tester {unique_id}",
        "role_type": "HR"
    })
    assert reg_res.status_code == 200
    
    # Get employee ID via admin
    emp_res = requests.get(f"{BASE_URL}/employees", headers={"Authorization": f"Bearer {admin_token}"})
    employees = emp_res.json()
    my_emp = next((e for e in employees if e["email"] == emp_email), None)
    assert my_emp is not None, "Registered employee must appear in employee list"
    emp_id = my_emp["id"]
    print(f"Employee registered: ID={emp_id}, Email={emp_email}")

    # 2. Ingest file deletion event with complete path
    del_event = {
        "employee_id": emp_id,
        "event_type": "file_delete",
        "filename": "Payroll_Q3_Confidential.xlsx",
        "extension": ".xlsx",
        "size": "2.4MB",
        "folder": "C:\\Users\\alokk\\OneDrive\\Desktop\\HR_Docs\\Payroll",
        "details": "File Delete: Payroll_Q3_Confidential.xlsx in HR_Docs\\Payroll"
    }
    
    evt_res = requests.post(f"{BASE_URL}/events", json=del_event)
    print("Single Event Ingest Response:", evt_res.status_code, evt_res.json())
    assert evt_res.status_code == 200
    created = evt_res.json()
    assert created.get("folder") == "C:\\Users\\alokk\\OneDrive\\Desktop\\HR_Docs\\Payroll"
    assert created.get("filename") == "Payroll_Q3_Confidential.xlsx"

    # 3. Batch Ingest file deletion events
    batch_payload = {
        "events": [
            {
                "employee_id": emp_id,
                "event_type": "file_delete",
                "filename": f"File{i}.txt",
                "extension": ".txt",
                "size": "100KB",
                "folder": "C:\\Users\\alokk\\Desktop\\ProjectData",
                "details": f"File Delete: File{i}.txt in ProjectData"
            }
            for i in range(1, 4)
        ]
    }
    batch_res = requests.post(f"{BASE_URL}/events/batch", json=batch_payload)
    print("Batch Event Ingest Response:", batch_res.status_code, batch_res.json())
    assert batch_res.status_code == 200

    # 4. Fetch employee detail and verify events
    detail_res = requests.get(f"{BASE_URL}/employees/{emp_id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert detail_res.status_code == 200
    detail = detail_res.json()
    events = detail.get("events", [])
    print(f"Total events recorded for employee #{emp_id}: {len(events)}")
    assert len(events) >= 4
    
    # Check folder path preservation
    first_del = next((e for e in events if e.get("filename") == "Payroll_Q3_Confidential.xlsx"), None)
    assert first_del is not None
    assert first_del.get("folder") == "C:\\Users\\alokk\\OneDrive\\Desktop\\HR_Docs\\Payroll"
    print(f"✓ Event verified with path: {first_del['filename']} at '{first_del['folder']}'")

    print("\n✓ ALL REAL-TIME STREAM & FILE DELETION PATH TESTS PASSED!")

if __name__ == "__main__":
    test_events_and_paths()
