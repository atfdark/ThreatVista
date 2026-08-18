import os
import sys
import uuid
import requests

BASE_URL = "http://127.0.0.1:8000/api"

def test_registration():
    print("=== Testing Employee Registration with Roles ===")
    
    unique_id = uuid.uuid4().hex[:6]
    
    # 1. Register HR Employee
    hr_email = f"nandini_{unique_id}@threatvista.com"
    hr_res = requests.post(f"{BASE_URL}/auth/register", json={
        "username": hr_email,
        "password": "password123",
        "name": "Nandini HR",
        "role_type": "HR"
    })
    print("HR Registration response:", hr_res.status_code, hr_res.json())
    assert hr_res.status_code == 200
    assert hr_res.json().get("role_type") == "HR"

    # 2. Register Developer Employee
    dev_email = f"rahul_{unique_id}@threatvista.com"
    dev_res = requests.post(f"{BASE_URL}/auth/register", json={
        "username": dev_email,
        "password": "password123",
        "name": "Rahul Dev",
        "role_type": "Developer"
    })
    print("Developer Registration response:", dev_res.status_code, dev_res.json())
    assert dev_res.status_code == 200
    assert dev_res.json().get("role_type") == "Developer"

    # 3. Login as HR
    login_res = requests.post(f"{BASE_URL}/auth/login", json={
        "username": hr_email,
        "password": "password123"
    })
    print("HR Login response:", login_res.status_code, login_res.json())
    assert login_res.status_code == 200
    assert login_res.json().get("role_type") == "HR"

    print("✓ Role-Based Registration & Login verified successfully!")

if __name__ == "__main__":
    test_registration()
