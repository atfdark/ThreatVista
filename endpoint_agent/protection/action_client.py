"""
ThreatVista Endpoint Action Request Client.

Manages real-time submission of intercepted actions (e.g. file deletions),
notifies the employee on their desktop, and processes Admin authorizations.
"""
import os
import sys
import json
import time
import threading
import requests
from typing import Set, Optional, Dict

from endpoint_agent.utils.sender import get_backend_url


class ActionProtectionClient:
    def __init__(self, vault, employee_id: Optional[int] = None, device_id: Optional[str] = None):
        self.vault = vault
        self.employee_id = employee_id
        self.device_id = device_id
        self.approved_paths: Set[str] = set()
        self._lock = threading.Lock()

    def set_identity(self, employee_id: int, device_id: Optional[str] = None):
        self.employee_id = employee_id
        self.device_id = device_id

    def is_approved(self, path: str) -> bool:
        with self._lock:
            norm = os.path.abspath(path).lower()
            return norm in self.approved_paths

    def allow_once(self, path: str):
        with self._lock:
            norm = os.path.abspath(path).lower()
            self.approved_paths.add(norm)

    def submit_action_request(
        self,
        target_file: str,
        file_path: str,
        action_type: str = "file_delete",
        file_size: Optional[str] = None,
        risk_context: Optional[str] = None,
    ) -> Optional[Dict]:
        """Submit pending action request ticket to backend."""
        if not self.employee_id:
            return None

        url = f"{get_backend_url()}/api/action-requests"
        payload = {
            "employee_id": self.employee_id,
            "device_id": self.device_id,
            "action_type": action_type,
            "target_file": target_file,
            "file_path": file_path,
            "file_size": file_size,
            "risk_context": risk_context or f"File deletion of '{target_file}' intercepted. Awaiting Admin Approval.",
        }

        try:
            resp = requests.post(url, json=payload, timeout=4)
            if resp.status_code == 200:
                data = resp.json()
                print(f"[🛡️ ThreatVista Protection] Action ticket #{data.get('id')} created for Admin approval.")
                self.notify_user_desktop(target_file, action_type)
                return data
        except Exception as e:
            print(f"[-] Failed to submit action ticket: {e}")

        return None

    def notify_user_desktop(self, target_file: str, action_type: str = "file_delete"):
        """Show non-blocking desktop toast or console alert to employee."""
        action_str = action_type.replace('_', ' ').title()
        msg = f"ThreatVista Security Alert:\n{action_str} on '{target_file}' requires Admin Authorization.\nA request has been submitted to your Security Administrator."
        print(f"\n=======================================================")
        print(f"[🛡️ THREATVISTA ACTIVE PROTECTION]")
        print(f"Action: {action_str} on '{target_file}'")
        print(f"Status: INTERCEPTED & RESTORED (Admin Approval Pending)")
        print(f"=======================================================\n")

        # Try displaying Windows Toast/MessageBox asynchronously if on Windows
        if sys.platform == "win32":
            def _async_msg():
                try:
                    import ctypes
                    ctypes.windll.user32.MessageBoxW(
                        0,
                        f"Action on '{target_file}' requires Admin Authorization.\n\nYour file has been preserved by ThreatVista Protection.",
                        "ThreatVista Security Alert",
                        0x30 | 0x10000  # MB_ICONWARNING | MB_SETFOREGROUND
                    )
                except Exception:
                    pass
            threading.Thread(target=_async_msg, daemon=True).start()

    def check_for_approvals(self):
        """Poll for recently approved action requests for this employee."""
        if not self.employee_id:
            return

        try:
            url = f"{get_backend_url()}/api/action-requests?employee_id={self.employee_id}&status=APPROVED&limit=10"
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                requests_list = resp.json()
                for req in requests_list:
                    path = req.get("file_path")
                    if path and not self.is_approved(path):
                        print(f"[+] Admin approved action #{req.get('id')} for: {path}")
                        self.allow_once(path)
                        # Execute the deletion now that Admin has approved
                        self.vault.purge_file(path)
        except Exception:
            pass
