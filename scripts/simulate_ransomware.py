import os
import time
import random

def get_target_dir():
    base = os.path.expanduser("~")
    # Prefer OneDrive Documents, fallback to local Documents
    docs = os.path.join(base, "OneDrive", "Documents")
    if not os.path.exists(docs):
        docs = os.path.join(base, "Documents")
    
    # We use 'finance' to trigger the directory anomaly rule
    target = os.path.join(docs, "finance")
    os.makedirs(target, exist_ok=True)
    return target

def simulate_ransomware():
    target_dir = get_target_dir()
    print(f"[*] Starting Ransomware Simulation in: {target_dir}")
    
    # 1. Drop 100 dummy files
    print("[*] Creating 100 dummy files (mass file activity)...")
    file_paths = []
    for i in range(1, 101):
        ext = random.choice([".docx", ".xlsx", ".pdf"])
        path = os.path.join(target_dir, f"q3_report_internal_{i}{ext}")
        with open(path, "w") as f:
            f.write("CONFIDENTIAL FINANCIAL DATA " * 50)
        file_paths.append(path)
        time.sleep(0.01) # Small delay to ensure events are captured sequentially
        
    print(f"[+] 100 files created.")
    time.sleep(2)
    
    # 2. Simulate rapid encryption (Rename + Modify)
    print("[*] Simulating rapid encryption phase (Ransomware behavior)...")
    for path in file_paths:
        try:
            enc_path = path + ".encrypted"
            # Rename file (Move event)
            os.rename(path, enc_path)
            # Rewrite content (Modify event)
            with open(enc_path, "w") as f:
                f.write("YOUR FILES HAVE BEEN ENCRYPTED! PAY 1 BTC TO RECOVER.")
            time.sleep(0.02)
        except Exception as e:
            print(f"[-] Error modifying {path}: {e}")
            
    print("[+] Ransomware simulation complete!")
    print("[!] Check the ThreatVista dashboard for anomalies and alerts.")

if __name__ == "__main__":
    simulate_ransomware()
