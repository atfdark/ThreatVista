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
        self.processed_ticket_ids: Set[int] = set()
        self.recent_intercepted: Dict[str, Dict] = {}  # filename_lower -> {time, path, action_type}
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

    def record_interception(self, filename: str, file_path: str, action_type: str):
        with self._lock:
            self.recent_intercepted[filename.lower()] = {
                "timestamp": time.time(),
                "file_path": file_path,
                "action_type": action_type,
            }

    def has_recent_usb_interception(self, filename: str, within_seconds: float = 10.0) -> bool:
        with self._lock:
            entry = self.recent_intercepted.get(filename.lower())
            if entry and (time.time() - entry["timestamp"] <= within_seconds):
                return True
            return False

    def submit_action_request(
        self,
        target_file: str,
        file_path: str,
        action_type: str = "file_delete",
        file_size: Optional[str] = None,
        risk_context: Optional[str] = None,
    ) -> Optional[Dict]:
        """Submit pending action request ticket to backend."""
        self.record_interception(target_file, file_path, action_type)

        if not self.employee_id:
            return None

        url = f"{get_backend_url()}/api/action-requests"
        default_context = (
            f"USB file transfer of '{target_file}' to removable drive intercepted. Awaiting Admin Approval."
            if action_type in ("usb_export", "usb_copy")
            else f"File deletion of '{target_file}' intercepted. Awaiting Admin Approval."
        )
        payload = {
            "employee_id": self.employee_id,
            "device_id": self.device_id,
            "action_type": action_type,
            "target_file": target_file,
            "file_path": file_path,
            "file_size": file_size,
            "risk_context": risk_context or default_context,
        }

        try:
            resp = requests.post(url, json=payload, timeout=4)
            if resp.status_code == 200:
                data = resp.json()
                print(f"[🛡️ ThreatVista Protection] Action ticket #{data.get('id')} ({action_type}) created for Admin approval.")
                self.notify_user_desktop(target_file, action_type, status="PENDING")
                return data
        except Exception as e:
            print(f"[-] Failed to submit action ticket: {e}")

        return None

    def notify_user_desktop(self, target_file: str, action_type: str = "file_delete", status: str = "PENDING"):
        """Show non-blocking desktop toast or console alert to employee."""
        action_label = "USB File Export" if action_type in ("usb_export", "usb_copy") else action_type.replace('_', ' ').title()
        status_label = "INTERCEPTED & QUARANTINED (Admin Approval Pending)" if status == "PENDING" else status.upper()

        print(f"\n=======================================================")
        print(f"[🛡️ THREATVISTA ACTIVE PROTECTION]")
        print(f"Action: {action_label} on '{target_file}'")
        print(f"Status: {status_label}")
        print(f"=======================================================\n")

        # Try displaying Windows Toast/MessageBox asynchronously if on Windows
        if sys.platform == "win32":
            def _async_msg():
                try:
                    import ctypes
                    if status == "PENDING":
                        msg_text = (
                            f"USB Transfer of '{target_file}' requires Security Admin Authorization.\n\n"
                            f"The file has been safely quarantined until approved."
                            if action_type in ("usb_export", "usb_copy")
                            else f"Action on '{target_file}' requires Admin Authorization.\n\nYour file has been preserved by ThreatVista Protection."
                        )
                        title_text = "ThreatVista Security Alert - Authorization Required"
                    elif status == "APPROVED":
                        msg_text = f"Admin APPROVED '{target_file}' {action_label}.\nOperation has been executed."
                        title_text = "ThreatVista - Action Approved"
                    else:
                        msg_text = f"Admin REJECTED '{target_file}' {action_label}.\nOperation has been blocked."
                        title_text = "ThreatVista - Action Blocked"

                    ctypes.windll.user32.MessageBoxW(
                        0,
                        msg_text,
                        title_text,
                        0x30 | 0x10000  # MB_ICONWARNING | MB_SETFOREGROUND
                    )
                except Exception:
                    pass
            threading.Thread(target=_async_msg, daemon=True).start()

    def check_for_approvals(self):
        """Poll for recently approved and rejected action requests for this employee."""
        if not self.employee_id:
            return

        # 1. Check APPROVED tickets
        try:
            url = f"{get_backend_url()}/api/action-requests?employee_id={self.employee_id}&status=APPROVED&limit=10"
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                requests_list = resp.json()
                for req in requests_list:
                    req_id = req.get("id")
                    if req_id in self.processed_ticket_ids:
                        continue

                    path = req.get("file_path")
                    target = req.get("target_file") or os.path.basename(path)
                    act_type = req.get("action_type", "file_delete")

                    if path:
                        print(f"[+] Admin APPROVED action #{req_id} ({act_type}) for: {path}")
                        self.allow_once(path)
                        self.processed_ticket_ids.add(req_id)

                        if act_type in ("usb_export", "usb_copy"):
                            # Release quarantined file back to USB drive
                            self.vault.release_quarantined_file(path)
                            self.notify_user_desktop(target, act_type, status="APPROVED")
                        elif act_type == "file_delete":
                            # Execute the deletion now that Admin has approved
                            self.vault.purge_file(path)
                            self.notify_user_desktop(target, act_type, status="APPROVED")
        except Exception:
            pass

        # 2. Check REJECTED tickets
        try:
            url = f"{get_backend_url()}/api/action-requests?employee_id={self.employee_id}&status=REJECTED&limit=10"
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                requests_list = resp.json()
                for req in requests_list:
                    req_id = req.get("id")
                    if req_id in self.processed_ticket_ids:
                        continue

                    path = req.get("file_path")
                    target = req.get("target_file") or os.path.basename(path)
                    act_type = req.get("action_type", "file_delete")

                    if path:
                        print(f"[-] Admin REJECTED action #{req_id} ({act_type}) for: {path}")
                        self.processed_ticket_ids.add(req_id)

                        if act_type in ("usb_export", "usb_copy"):
                            # Wipe/purge file from USB and purge quarantine
                            self.vault.purge_quarantined_file(path)
                            self.notify_user_desktop(target, act_type, status="REJECTED")
                        elif act_type == "file_delete":
                            # File is already restored on C: drive, just notify
                            self.notify_user_desktop(target, act_type, status="REJECTED")
        except Exception:
            pass

