import requests

BASE_URL = "http://127.0.0.1:8000/api"

# Login as admin
admin_res = requests.post(f"{BASE_URL}/auth/login", json={"username": "admin", "password": "admin123"})
print("Admin login status:", admin_res.status_code)
admin_token = admin_res.json().get("access_token")

# Get employees
emps_res = requests.get(f"{BASE_URL}/employees", headers={"Authorization": f"Bearer {admin_token}"})
print("Employees status:", emps_res.status_code)
employees = emps_res.json()

target_emp = next((e for e in employees if "tester_bd796f" in e.get("email", "") or "bd796f" in e.get("name", "")), None)
if not target_emp:
    print("Could not find tester_bd796f directly, listing all employees:")
    for e in employees:
        print(f" - ID: {e['id']}, Name: {e['name']}, Email: {e['email']}")
    if employees:
        target_emp = employees[-1]
        print(f"Using employee ID {target_emp['id']} ({target_emp['email']}) as test target")

if target_emp:
    del_res = requests.delete(f"{BASE_URL}/employees/{target_emp['id']}", headers={"Authorization": f"Bearer {admin_token}"})
    print("Delete status:", del_res.status_code)
    print("Delete text:", del_res.text)
