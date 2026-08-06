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

def is_path_excluded(path):
    if not path:
        return True
    path_lower = path.lower()
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
    def __init__(self, callback):
        self.callback = callback
        # Watch specific folders on C:\ plus all other full drives
        self.monitored_paths = get_user_dirs() + get_all_drive_paths()

    def on_created(self, event):
        if is_path_excluded(event.src_path): return
        if event.is_directory:
            self._emit("folder_create", event.src_path, event)
        else:
            self._emit("file_create", event.src_path, event)

    def on_deleted(self, event):
        if is_path_excluded(event.src_path): return
        if event.is_directory:
            self._emit("folder_delete", event.src_path, event)
        else:
            self._emit("file_delete", event.src_path, event)

    def on_modified(self, event):
        if is_path_excluded(event.src_path): return
        if not event.is_directory:
            self._emit("file_modify", event.src_path, event)

    def on_moved(self, event):
        if is_path_excluded(event.dest_path): return
        if event.is_directory:
            self._emit("folder_move", event.dest_path, event)
        else:
            self._emit("file_move", event.dest_path, event)

    def _emit(self, event_type, path, event):
        try:
            filename = os.path.basename(path)
            extension = os.path.splitext(filename)[1].lower()
            folder = os.path.dirname(path)

            size = None
            try:
                if os.path.exists(path):
                    size = os.path.getsize(path)
            except (OSError, PermissionError):
                pass
            size_str = f"{size / (1024*1024):.1f}MB" if size else "Unknown"

            self.callback({
                "event_type": event_type,
                "filename": filename,
                "extension": extension,
                "size": size_str,
                "folder": folder,
                "details": f"{event_type.replace('_', ' ').title()}: {filename} in {os.path.basename(folder)}"
            })
        except Exception as e:
            print(f"File monitor error: {e}")

def start_file_monitoring(callback):
    observer = Observer()
    handler = ThreatFileHandler(callback)
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
