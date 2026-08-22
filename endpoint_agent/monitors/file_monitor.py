import os
import time
import threading
from datetime import datetime
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# High-noise system directories to ignore, just in case they appear on other drives
EXCLUDED_PATHS = [
    "\\windows\\",
    "\\programdata\\",
    "\\appdata\\",
    "\\temp\\",
    "\\$recycle.bin\\",
    "\\system volume information\\",
    "\\node_modules\\"
]

import ctypes

def is_removable_drive_path(path: str) -> bool:
    """Check if a path resides on a removable/USB or external secondary drive."""
    if not path:
        return False
    drive, _ = os.path.splitdrive(path)
    if not drive:
        return False

    root = drive.rstrip("\\") + "\\"
    try:
        # Win32 GetDriveTypeW:
        # DRIVE_REMOVABLE = 2, DRIVE_FIXED = 3, DRIVE_REMOTE = 4, DRIVE_CDROM = 5, DRIVE_RAMDISK = 6
        drive_type = ctypes.windll.kernel32.GetDriveTypeW(root)
        if drive_type in (2, 4):  # Removable or Network share
            return True
    except Exception:
        pass

    # Any non-C: drive is treated as external storage
    if drive.upper() not in ("C:"):
        return True

    return False

def is_path_excluded(path):
    if not path:
        return True
    path_lower = os.path.normpath(path).lower()
    path_with_slash = path_lower if path_lower.endswith('\\') else path_lower + '\\'
    for excluded in EXCLUDED_PATHS:
        if excluded in path_with_slash:
            return True
    return False

def get_user_dirs():
    """Resolve the REAL Desktop/Documents/Downloads paths."""
    base = os.path.expanduser("~")
    groups = {
        "Desktop": [os.path.join(base, "OneDrive", "Desktop"), os.path.join(base, "Desktop")],
        "Documents": [os.path.join(base, "OneDrive", "Documents"), os.path.join(base, "Documents")],
        "Downloads": [os.path.join(base, "Downloads")],
    }
    dirs = []
    for candidates in groups.values():
        for p in candidates:
            if os.path.isdir(p):
                dirs.append(p)
                break
    return list(dict.fromkeys(dirs))

def get_all_drive_paths():
    """Return root paths of all connected drives EXCEPT the C: drive."""
    paths = []
    try:
        for part in psutil.disk_partitions(all=False):
            if part.mountpoint and os.path.isdir(part.mountpoint):
                # We skip C:\ entirely here. We will watch specific folders on C:\ instead.
                if part.mountpoint.upper().startswith("C:\\"):
                    continue
                paths.append(part.mountpoint)
    except Exception as exc:
        print(f"Drive scan error: {exc}")
    return paths

class ThreatFileHandler(FileSystemEventHandler):
    def __init__(self, callback, vault=None, action_client=None):
        self.callback = callback
        self.vault = vault
        self.action_client = action_client
        self._cooldown = {}  # key -> timestamp
        self._lock = threading.Lock()
        # Watch specific folders on C:\ plus all other full drives
        self.monitored_paths = get_user_dirs() + get_all_drive_paths()

    def _should_throttle_interception(self, path: str, filename: str, action: str = "usb_export", cooldown_secs: float = 15.0) -> bool:
        """Check if an interception for this file/path occurred within cooldown period."""
        now = time.time()
        p_key = (os.path.normpath(path).lower(), action)
        f_key = (filename.lower(), action)
        with self._lock:
            if p_key in self._cooldown and (now - self._cooldown[p_key] < cooldown_secs):
                return True
            if f_key in self._cooldown and (now - self._cooldown[f_key] < cooldown_secs):
                return True
            self._cooldown[p_key] = now
            self._cooldown[f_key] = now
            return False

    def _find_source_candidate(self, filename: str) -> Optional[str]:
        """Search local user directories (Downloads, Documents, Desktop) for original file location."""
        for u_dir in get_user_dirs():
            candidate = os.path.join(u_dir, filename)
            if os.path.isfile(candidate):
                return candidate
        return None

    def on_created(self, event):
        if is_path_excluded(event.src_path): return
        if event.is_directory:
            self._emit("folder_create", event.src_path, event)
        else:
            is_removable = is_removable_drive_path(event.src_path)
            is_approved = self.action_client and self.action_client.is_approved(event.src_path)

            if is_removable and not is_approved:
                filename = os.path.basename(event.src_path)
                if self._should_throttle_interception(event.src_path, filename, "usb_export"):
                    return  # Debounce duplicate chunk writes

                source_path = self._find_source_candidate(filename)
                size_str = None
                try:
                    if os.path.exists(event.src_path):
                        sz = os.path.getsize(event.src_path)
                        size_str = f"{sz / (1024*1024):.1f}MB" if sz else None
                except Exception:
                    pass

                if self.vault:
                    self.vault.quarantine_file(event.src_path, source_path=source_path)

                if self.action_client:
                    self.action_client.submit_action_request(
                        target_file=filename,
                        file_path=event.src_path,
                        action_type="usb_export",
                        file_size=size_str,
                        source_path=source_path,
                        risk_context=f"Unauthorized USB file transfer of '{filename}' to removable drive ({event.src_path}) intercepted and quarantined. Awaiting Admin Approval."
                    )
                self._emit("usb_export_intercepted", event.src_path, event)
            else:
                if self.vault:
                    self.vault.backup_file(event.src_path)
                self._emit("file_create", event.src_path, event)

    def on_deleted(self, event):
        if is_path_excluded(event.src_path): return
        if event.is_directory:
            self._emit("folder_delete", event.src_path, event)
        else:
            filename = os.path.basename(event.src_path)
            is_approved = self.action_client and self.action_client.is_approved(event.src_path)
            has_recent_usb = self.action_client and self.action_client.has_recent_usb_interception(filename)

            if not is_approved and self.vault:
                if has_recent_usb:
                    # Cross-drive move: restore source file immediately to avoid data loss
                    restored = False
                    if self.vault.has_backup(event.src_path):
                        restored = self.vault.restore_file(event.src_path)
                    else:
                        recent_info = self.action_client.get_recent_usb_interception(filename)
                        if recent_info and recent_info.get("file_path"):
                            restored = self.vault.restore_quarantined_to_source(recent_info["file_path"], event.src_path)

                    if restored:
                        print(f"[🛡️ ThreatVista Protection] Preserved local source file '{filename}' at {event.src_path} during USB transfer.")
                elif self.vault.has_backup(event.src_path):
                    # Unauthorized file deletion on endpoint -> restore from Shadow Vault
                    restored = self.vault.restore_file(event.src_path)
                    if restored and self.action_client:
                        self.action_client.submit_action_request(
                            target_file=filename,
                            file_path=event.src_path,
                            action_type="file_delete",
                            risk_context=f"Unauthorized deletion of '{filename}' intercepted. File restored from Shadow Vault awaiting Admin Approval."
                        )
            self._emit("file_delete", event.src_path, event)

    def on_modified(self, event):
        if is_path_excluded(event.src_path): return
        if not event.is_directory:
            is_removable = is_removable_drive_path(event.src_path)
            is_approved = self.action_client and self.action_client.is_approved(event.src_path)

            if is_removable and not is_approved:
                filename = os.path.basename(event.src_path)
                if self._should_throttle_interception(event.src_path, filename, "usb_export"):
                    return  # Debounce subsequent chunk writes for active pending transfer

                source_path = self._find_source_candidate(filename)
                if self.vault:
                    self.vault.quarantine_file(event.src_path, source_path=source_path)

                if self.action_client:
                    self.action_client.submit_action_request(
                        target_file=filename,
                        file_path=event.src_path,
                        action_type="usb_export",
                        source_path=source_path,
                        risk_context=f"Unauthorized write to USB file '{filename}' intercepted and quarantined. Awaiting Admin Approval."
                    )
                self._emit("usb_export_intercepted", event.src_path, event)
            else:
                if self.vault:
                    self.vault.backup_file(event.src_path)
                self._emit("file_modify", event.src_path, event)

    def on_moved(self, event):
        if is_path_excluded(event.dest_path): return
        if event.is_directory:
            self._emit("folder_move", event.dest_path, event)
        else:
            is_removable = is_removable_drive_path(event.dest_path)
            is_approved = self.action_client and self.action_client.is_approved(event.dest_path)

            if is_removable and not is_approved:
                filename = os.path.basename(event.dest_path)
                source_path = event.src_path if os.path.exists(event.src_path) else self._find_source_candidate(filename)

                if self._should_throttle_interception(event.dest_path, filename, "usb_export"):
                    return

                if self.vault:
                    self.vault.quarantine_file(event.dest_path, source_path=source_path)

                if self.action_client:
                    self.action_client.submit_action_request(
                        target_file=filename,
                        file_path=event.dest_path,
                        action_type="usb_export",
                        source_path=source_path,
                        risk_context=f"Unauthorized file move '{filename}' to removable drive intercepted. Awaiting Admin Approval."
                    )
                self._emit("usb_export_intercepted", event.dest_path, event)
            else:
                if self.vault:
                    self.vault.backup_file(event.dest_path)
                self._emit("file_move", event.dest_path, event)



    def _emit(self, event_type, path, event):
        try:
            filename = os.path.basename(path)
            extension = os.path.splitext(filename)[1].lower() if not event.is_directory else ""
            folder = path if event.is_directory else os.path.dirname(path)
            parent_folder = os.path.dirname(path)
            folder_label = os.path.basename(parent_folder) or parent_folder or "root"

            size_str = None
            if not event.is_directory:
                try:
                    if os.path.exists(path):
                        size = os.path.getsize(path)
                        size_str = f"{size / (1024*1024):.1f}MB" if size else None
                except (OSError, PermissionError):
                    pass

            self.callback({
                "event_type": event_type,
                "filename": filename,
                "extension": extension,
                "size": size_str,
                "folder": folder,
                "details": f"{event_type.replace('_', ' ').title()}: {path}" if event.is_directory else f"{event_type.replace('_', ' ').title()}: {filename} in {folder_label}"
            })
        except Exception as e:
            print(f"File monitor error: {e}")

def start_file_monitoring(callback, vault=None, action_client=None):
    observer = Observer()
    handler = ThreatFileHandler(callback, vault=vault, action_client=action_client)
    scheduled = set()
    _schedule_lock = threading.Lock()

    def schedule(path):
        """Schedule a directory tree on the observer exactly once."""
        with _schedule_lock:
            if path in scheduled or not os.path.isdir(path):
                return
            try:
                observer.schedule(handler, path, recursive=True)
                scheduled.add(path)
                print(f"[+] Watching {path}")
            except Exception as exc:
                print(f"[-] Failed to watch {path}: {exc}")

    # Initial scheduling
    for path in handler.monitored_paths:
        schedule(path)

    # Poll for any newly mounted non-C: drives (like USBs)
    def poll_drives():
        while True:
            time.sleep(3)
            for path in get_all_drive_paths():
                if path not in scheduled:
                    time.sleep(1)
                    schedule(path)

    threading.Thread(target=poll_drives, daemon=True).start()
    observer.start()
    return observer
