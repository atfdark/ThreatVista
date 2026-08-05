import os
import time
import threading
import sys
from datetime import datetime

from endpoint_agent.monitors.file_monitor import start_file_monitoring
from endpoint_agent.monitors.usb_monitor import USBMonitor
from endpoint_agent.monitors.process_monitor import ProcessMonitor
from endpoint_agent.monitors.system_monitor import (
    get_device_info,
    get_system_metrics,
    get_running_processes,
)
from endpoint_agent.utils.sender import (
    send_event,
    send_heartbeat,
    register_device,
    check_backend_health,
)

# Which employee this machine belongs to. Override with AGENT_EMPLOYEE_EMAIL.
EMPLOYEE_EMAIL = os.environ.get("AGENT_EMPLOYEE_EMAIL", "rahul.sharma@threatvista.com")
HEARTBEAT_SECONDS = int(os.environ.get("AGENT_HEARTBEAT_SECONDS", "30"))


class EndpointAgent:
    def __init__(self):
        self.running = False
        self.employee_id = None
        self.device_id = None
        self._usb_monitor = None

    def _event_callback(self, event_data):
        event_data["employee_id"] = self.employee_id
        event_data.setdefault("timestamp", datetime.utcnow().isoformat())

        if "cpu_usage" not in event_data or "ram_usage" not in event_data:
            metrics = get_system_metrics()
            event_data.setdefault("cpu_usage", metrics.get("cpu_usage"))
            event_data.setdefault("ram_usage", metrics.get("ram_usage"))

        send_event(event_data)

    def _register(self):
        """Register this machine's device and resolve the employee identity."""
        device_info = get_device_info()
        device_id, err = register_device(EMPLOYEE_EMAIL, device_info)
        if err:
            print(f"[!] Device registration failed: {err}")
            return
        self.device_id = device_id
        print(f"[+] Registered device {device_id} for {EMPLOYEE_EMAIL}")

    def start(self):
        print(f"[*] ThreatVista Endpoint Agent starting for {EMPLOYEE_EMAIL}")
        if not check_backend_health():
            print("[!] Backend not reachable. Events will be queued locally (not implemented in Phase 2).")
            self.employee_id = 1  # fall back so the agent can still attempt sends
        else:
            print("[+] Backend connected.")
            self._register()

        # Resolve employee id from the employee directory when possible.
        if self.employee_id is None:
            try:
                from endpoint_agent.utils.sender import API_BASE_URL
                import requests
                emps = requests.get(f"{API_BASE_URL}/employees", timeout=5).json()
                for emp in emps:
                    if emp.get("email", "").lower() == EMPLOYEE_EMAIL.lower():
                        self.employee_id = emp["id"]
                        break
            except Exception:
                pass
            if self.employee_id is None:
                self.employee_id = 1  # default (single-machine demo)

        self.running = True

        # Heartbeat loop — keeps this device "online" in the SOC dashboard.
        def heartbeat_loop():
            while self.running:
                try:
                    if self.device_id:
                        metrics = get_system_metrics()
                        send_heartbeat(self.device_id, {
                            "cpu_usage": metrics.get("cpu_usage"),
                            "ram_usage": metrics.get("ram_usage"),
                            "disk_usage": metrics.get("disk_usage"),
                        })
                except Exception as e:
                    print(f"Heartbeat error: {e}")
                time.sleep(HEARTBEAT_SECONDS)

        threading.Thread(target=heartbeat_loop, daemon=True).start()

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
