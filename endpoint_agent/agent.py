import os
import sys

# When launched directly as a script (`python endpoint_agent/agent.py`), Python
# only puts the endpoint_agent/ folder on sys.path, not the project root that
# the `endpoint_agent.*` package imports need. Put the root back so direct
# launches work the same as `python -m endpoint_agent.agent`.
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from endpoint_agent.utils import enrollment
from endpoint_agent.utils.sender import (
    send_event_batch,
    send_heartbeat,
    register_device_with_token,
    check_backend_health,
    set_backend_url,
    get_backend_url,
)
from endpoint_agent.utils.batcher import EventBatcher
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
from endpoint_agent.protection.vault import ShadowVault
from endpoint_agent.protection.action_client import ActionProtectionClient

HEARTBEAT_SECONDS = int(os.environ.get("AGENT_HEARTBEAT_SECONDS", "30"))


class EndpointAgent:
    def __init__(self, backend_url_override: str = None):
        self.running = False
        self.employee_id = None
        self.device_id = None
        self._usb_monitor = None
        self.enrollment = enrollment.load_enrollment_config()
        self.device_identity = enrollment.load_device_identity()

        # Prioritize CLI argument > enrollment file > device identity > env var
        initial_url = (
            backend_url_override
            or (self.enrollment.get("backend_url") if self.enrollment else None)
            or (self.device_identity.get("backend_url") if self.device_identity else None)
            or os.environ.get("BACKEND_URL", "http://127.0.0.1:8000")
        )
        set_backend_url(initial_url)

        # Active Protection & JIT Authorization components
        self.vault = ShadowVault()
        self.action_client = ActionProtectionClient(self.vault)

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

    def _ensure_backend_connected(self) -> bool:
        """Verify backend connectivity. If unreachable, prompt the user for the new IP/URL."""
        if check_backend_health():
            return True

        current = get_backend_url()
        print(f"\n[!] Could not reach ThreatVista backend at: {current}")
        print("    The server IP may have changed, or you are connected to a different network.")
        print("    Hints:")
        print("      * Same Wi-Fi : Enter the server laptop's new IP (e.g. http://10.157.56.246:8000)")
        print("      * Remote / WAN: Enter your ngrok/tunnel URL (e.g. https://xyz.ngrok-free.app)")

        while True:
            try:
                user_input = input("\n[?] Enter new Backend IP/URL (Press Enter to retry current, 'q' to quit): ").strip()
            except (KeyboardInterrupt, EOFError):
                return False

            if user_input.lower() in ("q", "quit", "exit"):
                return False

            if user_input:
                candidate = user_input
                if not (candidate.startswith("http://") or candidate.startswith("https://")):
                    candidate = f"http://{candidate}"
                print(f"[*] Testing connection to {candidate}...")
                if check_backend_health(candidate):
                    set_backend_url(candidate)
                    enrollment.update_device_backend_url(candidate)
                    print(f"[+] Successfully connected to {candidate}!")
                    return True
                else:
                    print(f"[-] Still cannot reach {candidate}. Ensure backend is running and reachable.")
            else:
                print(f"[*] Retrying connection to {get_backend_url()}...")
                if check_backend_health():
                    print("[+] Backend connected.")
                    return True
                print("[-] Unreachable.")

    def _register(self):
        """Resolve this machine's device + employee identity."""
        if self.enrollment:
            device_info = get_device_info()
            result, err = register_device_with_token(self.enrollment["token"], device_info)
            if err:
                print(f"[!] Enrollment token rejected: {err}")
                enrollment.delete_enrollment_config(self.enrollment)
                if self.device_identity:
                    self.device_id = self.device_identity["device_id"]
                    self.employee_id = self.device_identity["employee_id"]
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
                "backend_url": get_backend_url(),
            })
            # The token is single-use; remove the file so it can never be reused.
            enrollment.delete_enrollment_config(self.enrollment)
            return True

        if self.device_identity:
            self.device_id = self.device_identity["device_id"]
            self.employee_id = self.device_identity["employee_id"]
            print(f"[+] Reconnecting to device {self.device_id} (employee #{self.employee_id}) — no re-enrollment needed")
            return True

        print("[!] No enrollment config found.")
        print("    Log in to ThreatVista, open your profile, click 'Connect This Device',")
        print("    download the config file, then run start_agent.bat again.")
        return False

    def start(self):
        backend_label = get_backend_url()
        print(f"[*] ThreatVista Endpoint Agent starting (backend: {backend_label})")
        if self.enrollment:
            print(f"[*] Found enrollment config at: {self.enrollment['path']}")

        if not (self.enrollment or self.device_identity):
            print("[!] This laptop is not enrolled yet.")
            print("    1. Log in to ThreatVista in a browser.")
            print("    2. Open your profile and click 'Connect This Device'.")
            print("    3. Keep threatvista-agent-config.json next to this folder (or in Downloads).")
            print("    4. Run start_agent.bat again.")
            return

        if not self._ensure_backend_connected():
            print("[!] Backend unreachable. Agent exiting.")
            return

        print(f"[+] Backend connected ({get_backend_url()}).")
        if not self._register():
            return  # token rejected / no identity — do not monitor under a wrong employee

        self.running = True
        self.action_client.set_identity(self.employee_id, self.device_id)

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

        # Action approval polling loop (syncs with Admin approvals)
        def approval_loop():
            while self.running:
                try:
                    self.action_client.check_for_approvals()
                except Exception:
                    pass
                time.sleep(3)

        threading.Thread(target=approval_loop, daemon=True).start()

        # File monitoring with Active Protection & Shadow Vault
        file_observer = start_file_monitoring(
            self._event_callback,
            vault=self.vault,
            action_client=self.action_client
        )
        print("[+] File monitor & Active Shadow Vault started")

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
    cli_url = None
    if len(sys.argv) > 1:
        args = sys.argv[1:]
        for i, arg in enumerate(args):
            if arg in ("--backend-url", "-b", "--url") and i + 1 < len(args):
                cli_url = args[i + 1]
                break
            elif not arg.startswith("-"):
                cli_url = arg
                break

    agent = EndpointAgent(backend_url_override=cli_url)
    agent.start()
