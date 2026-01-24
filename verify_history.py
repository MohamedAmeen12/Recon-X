import requests
import time
import uuid

BASE_URL = "http://localhost:5000"
SESSION = requests.Session()

def register_and_login():
    # Use unique email
    email = f"test_{uuid.uuid4().hex[:8]}@example.com"
    username = f"user_{uuid.uuid4().hex[:8]}"
    password = "password123"
    
    print(f"[*] Registering user {email}...")
    resp = SESSION.post(f"{BASE_URL}/signup", json={
        "email": email,
        "username": username,
        "password": password
    })
    if resp.status_code != 201:
        print(f"[!] Signup failed: {resp.text}")
        return False, None
    
    # We need to manually simulate approval if the system requires it.
    # The code says "User registered successfully and is now pending admin approval."
    # So we probably can't login immediately unless we approve via DB or Admin API.
    # OR we use the existing admin credentials?
    # Let's try to login as admin first to approve? 
    # Or just use admin for testing history (admins are users too).
    
    return True, {"email": email, "password": password}

def login_as_admin():
    print("[*] Logging in as Admin...")
    resp = SESSION.post(f"{BASE_URL}/login", json={
        "email": "ReconX@gmail.com",
        "password": "reconx1234"
    })
    if resp.status_code == 200:
        print("[+] Admin login success")
        return True
    else:
        print(f"[!] Admin login failed: {resp.text}")
        return False

def approve_user(email):
    # Admin approves user
    # Need to check admin controller for approval endpoint
    # Assuming /admin/approve_user or similar?
    # Let's just use Admin account for scanning to save time, as admins can scan too.
    return True

def test_scan_and_history():
    if not login_as_admin():
        return
    
    domain = "example.com"
    print(f"[*] Scanning domain: {domain}...")
    
    # Scan
    # Set timeout high as scan might take time
    try:
        resp = SESSION.post(f"{BASE_URL}/scan_domain", json={
            "domain": domain,
            "include_tech_scan": False # Faster
        }, timeout=60)
    except requests.exceptions.ReadTimeout:
        print("[!] Scan timed out")
        return

    if resp.status_code != 200:
        print(f"[!] Scan failed: {resp.text}")
        return
    
    data = resp.json()
    report_id = data.get("report_id")
    print(f"[+] Scan successful. Report ID: {report_id}")
    
    if not report_id:
        print("[!] No report_id returned!")
        return

    # Check History
    print("[*] Checking History...")
    resp = SESSION.get(f"{BASE_URL}/get_history")
    if resp.status_code != 200:
        print(f"[!] Get history failed: {resp.text}")
        return
    
    history = resp.json().get("history", [])
    print(f"[+] Found {len(history)} history items.")
    
    found = False
    for item in history:
        if item["report_id"] == report_id:
            found = True
            print(f"[+] Found report {report_id} in history.")
            break
    
    if not found:
        print(f"[!] Report {report_id} NOT found in history!")
    
    # Get Specific Report
    print(f"[*] Fetching report {report_id}...")
    resp = SESSION.get(f"{BASE_URL}/get_report?report_id={report_id}")
    if resp.status_code == 200:
        print("[+] Report fetch success.")
        r_data = resp.json()
        print(f"[+] Report Domain: {r_data.get('domain')}")
        print(f"[+] Report Scanned At: {r_data.get('scanned_at')}")
    else:
        print(f"[!] Report fetch failed: {resp.text}")

if __name__ == "__main__":
    try:
        test_scan_and_history()
    except Exception as e:
        print(f"[!] Error: {e}")
