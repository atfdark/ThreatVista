import requests

BASE_URL = "http://127.0.0.1:8000/api"

def test_delete_and_reuse():
    print("=== Testing Complete Employee Deletion & Demo Email Reuse ===")
    
    # 1. Admin login
    admin_res = requests.post(f"{BASE_URL}/auth/login", json={"username": "admin", "password": "admin123"})
    assert admin_res.status_code == 200, f"Admin login failed: {admin_res.text}"
    admin_token = admin_res.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    test_email = "demo_candidate@threatvista.com"
    test_name = "Demo Candidate"

    # Clean up any existing test user if present
    emps = requests.get(f"{BASE_URL}/employees", headers=admin_headers).json()
    existing = next((e for e in emps if e["email"] == test_email), None)
    if existing:
        del_res = requests.delete(f"{BASE_URL}/employees/{existing['id']}", headers=admin_headers)
        print("Cleaned up previous existing candidate:", del_res.status_code)

    # 2. Register test employee for demo
    reg_res = requests.post(f"{BASE_URL}/auth/register", json={
        "username": test_email,
        "password": "demoPassword123!",
        "name": test_name,
        "role_type": "Developer"
    })
    assert reg_res.status_code == 200, f"Register failed: {reg_res.text}"
    emp_token = reg_res.json()["access_token"]
    print("1. Employee registered successfully.")

    # Get employee ID
    emps = requests.get(f"{BASE_URL}/employees", headers=admin_headers).json()
    my_emp = next((e for e in emps if e["email"] == test_email), None)
    assert my_emp is not None
    emp_id = my_emp["id"]
    print(f"2. Employee found: ID={emp_id}, Name={test_name}")

    # 3. Create a test event and incident for this employee
    evt_res = requests.post(f"{BASE_URL}/events", json={
        "employee_id": emp_id,
        "event_type": "file_create",
        "filename": "demo_test.py",
        "folder": "C:\\Projects",
        "details": "Demo test file creation"
    })
    assert evt_res.status_code == 200
    print("3. Sample telemetry ingested.")

    # 4. Admin deletes the employee
    delete_res = requests.delete(f"{BASE_URL}/employees/{emp_id}", headers=admin_headers)
    assert delete_res.status_code == 200, f"Delete failed: {delete_res.text}"
    print(f"4. Delete response: {delete_res.json()}")

    # 5. Verify employee no longer exists in /employees
    emps_after = requests.get(f"{BASE_URL}/employees", headers=admin_headers).json()
    assert not any(e["id"] == emp_id for e in emps_after), "Employee must not exist after deletion"
    print("5. Confirmed employee removed from Monitored Directory.")

    # 6. Re-register the EXACT same email and name with a different role to prove demo reuse works!
    reuse_res = requests.post(f"{BASE_URL}/auth/register", json={
        "username": test_email,
        "password": "newDemoPassword456!",
        "name": test_name,
        "role_type": "HR"
    })
    assert reuse_res.status_code == 200, f"Failed to reuse email: {reuse_res.text}"
    print("6. ✓ Successfully re-registered demo employee with the same email and name!")

    # Clean up
    emps_final = requests.get(f"{BASE_URL}/employees", headers=admin_headers).json()
    reused_emp = next((e for e in emps_final if e["email"] == test_email), None)
    if reused_emp:
        requests.delete(f"{BASE_URL}/employees/{reused_emp['id']}", headers=admin_headers)
        print("7. Cleaned up demo test account.")

    print("\n✓ ALL EMPLOYEE DELETION AND DEMO REUSE TESTS PASSED!")

if __name__ == "__main__":
    test_delete_and_reuse()
