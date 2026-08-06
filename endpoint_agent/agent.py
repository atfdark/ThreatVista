import os
import sys

# When launched directly as a script (`python endpoint_agent/agent.py`), Python
# only puts the endpoint_agent/ folder on sys.path, not the project root that
# the `endpoint_agent.*` package imports need. Put the root back so direct
# launches work the same as `python -m endpoint_agent.agent`.
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Resolve which backend + identity to use BEFORE importing sender.py, which
# bakes API_BASE_URL from the BACKEND_URL environment variable at import time.
from endpoint_agent.utils import enrollment

ENROLLMENT = enrollment.load_enrollment_config()   # freshly downloaded token
DEVICE_IDENTITY = enrollment.load_device_identity()  # already-registered device
if ENROLLMENT:
    os.environ["BACKEND_URL"] = ENROLLMENT["backend_url"]
elif DEVICE_IDENTITY and DEVICE_IDENTITY.get("backend_url"):
    os.environ["BACKEND_URL"] = DEVICE_IDENTITY["backend_url"]

import time
import threading
from datetime import datetime

from endpoint_agent.monitors.file_monitor import start_file_monitoring
from endpoint_agent.monitors.usb_monitor import USBMonitor
from endpoint_agent.monitors.process_monitor import ProcessMonitor
from endpoint_agent.monitors.network_monitor import NetworkMonitor
from endpoint_agent.monitors.system_monitor import (
    get_device_info,
    get_system_metrics,
    get_running_processes,
)
from endpoint_agent.utils.sender import (
    send_event_batch,
    send_heartbeat,
    register_device_with_token,
    check_backend_health,
)
from endpoint_agent.utils.batcher import EventBatcher

HEARTBEAT_SECONDS = int(os.environ.get("AGENT_HEARTBEAT_SECONDS", "30"))


class EndpointAgent:
    def __init__(self):
        self.running = False
        self.employee_id = None
        self.device_id = None
        self._usb_monitor = None
        # Collect telemetry for ~1s (or 100 events) and send it as one bulk
        # request instead of one HTTP POST per event.
        self._batcher = EventBatcher(send_event_batch)

    def _event_callback(self, event_data):
        event_data["employee_id"] = self.employee_id
        event_data.setdefault("timestamp", datetime.utcnow().isoformat())

        if "cpu_usage" not in event_data or "ram_usage" not in event_data:
            metrics = get_system_metrics()
            event_data.setdefault("cpu_usage", metrics.get("cpu_usage"))
            event_data.setdefault("ram_usage", metrics.get("ram_usage"))

        self._batcher.add(event_data)

    def _register(self):
        """Resolve this machine's device + employee identity.

        Preferred path: an enrollment token freshly downloaded from the employee
        profile page. The backend validates/consumes it and returns the real
        employee id, which we persist so the next run simply reconnects to the
        same device (no duplicate registration, no re-enrollment).
        """
        if ENROLLMENT:
            device_info = get_device_info()
            result, err = register_device_with_token(ENROLLMENT["token"], device_info)
            if err:
                # The token was rejected (expired / already used / unknown).
                # Drop the stale file so it stops failing, then — if this laptop
                # was already enrolled — just reconnect instead of asking the
                # employee to click "Connect This Device" again.
                print(f"[!] Enrollment token rejected: {err}")
                enrollment.delete_enrollment_config(ENROLLMENT)
                if DEVICE_IDENTITY:
                    self.device_id = DEVICE_IDENTITY["device_id"]
                    self.employee_id = DEVICE_IDENTITY["employee_id"]
                    print(f"[+] This laptop is already enrolled — reconnecting to device {self.device_id} "
                          f"(employee #{self.employee_id}).")
                    print("    You do NOT need to click 'Connect This Device' again.")
                    return True
                print("    Get a fresh token: log in to ThreatVista, open your profile, click")
                print("    'Connect This Device', then run start_agent.bat again.")
                return False
            self.device_id = result.get("device_id")
            self.employee_id = result.get("employee_id")
            employee_name = result.get("employee_name", "?")
            print(f"[+] Registered device {self.device_id} for employee #{self.employee_id} ({employee_name})")
            enrollment.save_device_identity({
                "device_id": self.device_id,
                "employee_id": self.employee_id,
                "backend_url": ENROLLMENT["backend_url"],
            })
            # The token is single-use; remove the file so it can never be reused.
            enrollment.delete_enrollment_config(ENROLLMENT)
            return True

        if DEVICE_IDENTITY:
            self.device_id = DEVICE_IDENTITY["device_id"]
            self.employee_id = DEVICE_IDENTITY["employee_id"]
            print(f"[+] Reconnecting to device {self.device_id} (employee #{self.employee_id}) — no re-enrollment needed")
            return True

        print("[!] No enrollment config found.")
        print("    Log in to ThreatVista, open your profile, click 'Connect This Device',")
        print("    download the config file, then run start_agent.bat again.")
        return False

    def start(self):
        backend_label = (
            ENROLLMENT["backend_url"] if ENROLLMENT
            else (DEVICE_IDENTITY or {}).get("backend_url", "?")
        )
        print(f"[*] ThreatVista Endpoint Agent starting (backend: {backend_label})")
        if ENROLLMENT:
            print(f"[*] Found enrollment config at: {ENROLLMENT['path']}")

        if not (ENROLLMENT or DEVICE_IDENTITY):
            print("[!] This laptop is not enrolled yet.")
            print("    1. Log in to ThreatVista in a browser.")
            print("    2. Open your profile and click 'Connect This Device'.")
            print("    3. Keep threatvista-agent-config.json next to this folder (or in Downloads).")
            print("    4. Run start_agent.bat again.")
            return

        if not check_backend_health():
            print("[!] Backend not reachable. Start the ThreatVista backend, then run this again.")
            print("    Events are NOT queued locally, so nothing will be sent while offline.")
            return

        print("[+] Backend connected.")
        if not self._register():
            return  # token rejected / no identity — do not monitor under a wrong employee

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

        # Network upload monitoring (machine-wide outbound traffic).
        self._net_monitor = NetworkMonitor(self._event_callback)

        def network_loop():
            while self.running:
                try:
                    self._net_monitor.check_once()
                except Exception as e:
                    print(f"Network monitor error: {e}")
                time.sleep(NetworkMonitor.POLL_SECONDS)

        threading.Thread(target=network_loop, daemon=True).start()

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
        self._batcher.stop()
        print("\n[*] Stopping endpoint agent...")

if __name__ == "__main__":
    agent = EndpointAgent()
    agent.start()
