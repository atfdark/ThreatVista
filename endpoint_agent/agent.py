import time
import threading
import signal
import sys
from datetime import datetime

from endpoint_agent.monitors.file_monitor import start_file_monitoring
from endpoint_agent.monitors.usb_monitor import USBMonitor
from endpoint_agent.monitors.process_monitor import ProcessMonitor
from endpoint_agent.monitors.system_monitor import get_system_metrics, get_running_processes
from endpoint_agent.utils.sender import send_event, check_backend_health

EMPLOYEE_ID = 1
BACKEND_URL = "http://127.0.0.1:8000/api"

class EndpointAgent:
    def __init__(self):
        self.running = False
        self._usb_monitor = None

    def _event_callback(self, event_data):
        event_data["employee_id"] = EMPLOYEE_ID
        event_data.setdefault("timestamp", datetime.utcnow().isoformat())

        if "cpu_usage" not in event_data or "ram_usage" not in event_data:
            metrics = get_system_metrics()
            event_data.setdefault("cpu_usage", metrics.get("cpu_usage"))
            event_data.setdefault("ram_usage", metrics.get("ram_usage"))

        send_event(event_data)

    def start(self):
        print(f"[*] ThreatVista Endpoint Agent starting for employee {EMPLOYEE_ID}")
        if not check_backend_health():
            print("[!] Backend not reachable. Events will be queued locally (not implemented in Phase 2).")
        else:
            print("[+] Backend connected.")

        self.running = True

        # File monitoring
        file_observer = start_file_monitoring(self._event_callback)
        print("[+] File monitor started")

        # USB monitoring
        self._usb_monitor = USBMonitor(self._event_callback)
        if self._usb_monitor.start():
            print("[+] USB monitor started")
        else:
            print("[-] USB monitor not available (requires Windows with pywin32/WMI)")

        # Process monitoring
        self._proc_monitor = ProcessMonitor(self._event_callback)
        print("[+] Process monitor started")

        # System metrics loop
        def system_loop():
            while self.running:
                try:
                    metrics = get_system_metrics()
                    self._event_callback({
                        "event_type": "system_metrics",
                        "cpu_usage": metrics.get("cpu_usage"),
                        "ram_usage": metrics.get("ram_usage"),
                        "details": f"CPU: {metrics.get('cpu_usage')}%, RAM: {metrics.get('ram_usage')}%"
                    })
                except Exception as e:
                    print(f"System metrics error: {e}")
                time.sleep(60)

        threading.Thread(target=system_loop, daemon=True).start()

        # Process check loop
        def process_loop():
            while self.running:
                try:
                    self._proc_monitor.check_once()
                except Exception as e:
                    print(f"Process check error: {e}")
                time.sleep(10)

        threading.Thread(target=process_loop, daemon=True).start()

        # Main loop
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
        finally:
            file_observer.stop()
            file_observer.join()
            if self._usb_monitor:
                self._usb_monitor.stop()

    def stop(self):
        self.running = False
        print("\n[*] Stopping endpoint agent...")

if __name__ == "__main__":
    agent = EndpointAgent()
    agent.start()
