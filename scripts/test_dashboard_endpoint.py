import requests

BASE_URL = "http://127.0.0.1:8000/api"

# Login as admin
admin_res = requests.post(f"{BASE_URL}/auth/login", json={"username": "admin", "password": "admin123"})
print("Login status:", admin_res.status_code)
token = admin_res.json().get("access_token")

# Fetch dashboard
dash_res = requests.get(f"{BASE_URL}/dashboard", headers={"Authorization": f"Bearer {token}"})
print("Dashboard status:", dash_res.status_code)
print("Dashboard text:", dash_res.text)
if dash_res.status_code == 200:
    print("Dashboard data:", dash_res.json())
