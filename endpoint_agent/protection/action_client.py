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
        self.recent_intercepted: Dict[str, Dict] = {}  # filename_lower -> {time, path, action_type, source_path}
        self.pending_submissions: Dict[str, Dict] = {}  # key -> {timestamp, ticket}
        self.file_source_map: Dict[str, str] = {}  # filename_lower / target_path_lower -> source_path
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

    def record_interception(self, filename: str, file_path: str, action_type: str, source_path: Optional[str] = None):
        with self._lock:
            fn_key = filename.lower()
            fp_key = os.path.abspath(file_path).lower() if file_path else fn_key
            self.recent_intercepted[fn_key] = {
                "timestamp": time.time(),
                "file_path": file_path,
                "action_type": action_type,
                "source_path": source_path,
            }
            if source_path:
                self.file_source_map[fn_key] = source_path
                self.file_source_map[fp_key] = source_path

    def get_source_path(self, target_file: str, file_path: Optional[str] = None) -> Optional[str]:
        with self._lock:
            fn_key = target_file.lower()
            if fn_key in self.file_source_map:
                return self.file_source_map[fn_key]
            if file_path:
                fp_key = os.path.abspath(file_path).lower()
                if fp_key in self.file_source_map:
                    return self.file_source_map[fp_key]
        
        # Fallback: check user's standard Downloads/Desktop/Documents
        base = os.path.expanduser("~")
        for candidate_dir in [
            os.path.join(base, "Downloads"),
            os.path.join(base, "OneDrive", "Desktop"),
            os.path.join(base, "Desktop"),
            os.path.join(base, "OneDrive", "Documents"),
            os.path.join(base, "Documents"),
        ]:
            candidate_path = os.path.join(candidate_dir, target_file)
            if os.path.exists(candidate_path):
                return candidate_path
        # Default destination fallback is Downloads if nothing else exists
        return os.path.join(base, "Downloads", target_file)

    def has_recent_usb_interception(self, filename: str, within_seconds: float = 15.0) -> bool:
        with self._lock:
            entry = self.recent_intercepted.get(filename.lower())
            if entry and (time.time() - entry["timestamp"] <= within_seconds):
                return True
            return False

    def get_recent_usb_interception(self, filename: str) -> Optional[Dict]:
        with self._lock:
            return self.recent_intercepted.get(filename.lower())

    def submit_action_request(
        self,
        target_file: str,
        file_path: str,
        action_type: str = "file_delete",
        file_size: Optional[str] = None,
        risk_context: Optional[str] = None,
        source_path: Optional[str] = None,
    ) -> Optional[Dict]:
        """Submit pending action request ticket to backend with client-side debounce."""
        self.record_interception(target_file, file_path, action_type, source_path=source_path)

        if not self.employee_id:
            return None

        # Client-side debounce: If same target & action was submitted in last 15s, return cached
        cache_key = f"{target_file.lower()}:{action_type}"
        now = time.time()
        with self._lock:
            cached = self.pending_submissions.get(cache_key)
            if cached and (now - cached["timestamp"] < 15.0):
                return cached.get("ticket")

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
                with self._lock:
                    self.pending_submissions[cache_key] = {"timestamp": now, "ticket": data}
                print(f"[🛡️ ThreatVista Protection] Action ticket #{data.get('id')} ({action_type}) active for Admin approval.")
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
                            f"The file has been safely quarantined until approved.\n"
                            f"Your local working copy is preserved."
                            if action_type in ("usb_export", "usb_copy")
                            else f"Action on '{target_file}' requires Admin Authorization.\n\nYour file has been preserved by ThreatVista Protection."
                        )
                        title_text = "ThreatVista Security Alert - Authorization Required"
                    elif status == "APPROVED":
                        msg_text = f"Admin APPROVED '{target_file}' {action_label}.\nOperation has been executed."
                        title_text = "ThreatVista - Action Approved"
                    else:
                        msg_text = (
                            f"Admin REJECTED '{target_file}' {action_label}.\n\n"
                            f"The USB transfer was blocked. Your local file has been preserved."
                            if action_type in ("usb_export", "usb_copy")
                            else f"Admin REJECTED '{target_file}' {action_label}.\nOperation has been blocked."
                        )
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
                            # Wipe/purge file from USB and purge quarantine, preserving local source
                            source_path = self.get_source_path(target, path)
                            self.vault.purge_quarantined_file(path, fallback_source_path=source_path)
                            self.notify_user_desktop(target, act_type, status="REJECTED")
                        elif act_type == "file_delete":
                            # File is already restored on C: drive, just notify
                            self.notify_user_desktop(target, act_type, status="REJECTED")
        except Exception:
            pass


