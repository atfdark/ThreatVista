import os
import time
import threading
from datetime import datetime
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileDeletedEvent, FileModifiedEvent, FileMovedEvent

def get_removable_drive_paths():
    """Return root paths of currently-connected removable drives (USB sticks).

    psutil marks Windows removable disks (DriveType=2) with an 'removable' opts
    flag — the same drive class the USB monitor reports as usb_insert. On
    Linux/macOS this list is simply empty, which is harmless.
    """
    paths = []
    try:
        for part in psutil.disk_partitions():
            opts = (part.opts or "").split(",")
            if "removable" in opts and os.path.isdir(part.mountpoint):
                paths.append(part.mountpoint)
    except Exception as exc:
        print(f"Removable drive scan error: {exc}")
    return paths

class ThreatFileHandler(FileSystemEventHandler):
    def __init__(self, callback, monitored_paths=None):
        self.callback = callback
        self.monitored_paths = monitored_paths or [os.path.expanduser("~/Desktop"), os.path.expanduser("~/Documents"), os.path.expanduser("~/Downloads")]

    def on_created(self, event):
        if not event.is_directory:
            self._emit("file_create", event.src_path, event)

    def on_deleted(self, event):
        if not event.is_directory:
            self._emit("file_delete", event.src_path, event)

    def on_modified(self, event):
        if not event.is_directory:
            self._emit("file_modify", event.src_path, event)

    def on_moved(self, event):
        if not event.is_directory:
            self._emit("file_move", event.dest_path, event)

    def _emit(self, event_type, path, event):
        try:
            filename = os.path.basename(path)
            extension = os.path.splitext(filename)[1].lower()
            folder = os.path.dirname(path)
            size = os.path.getsize(path) if os.path.exists(path) else None
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

    def schedule(path):
        """Schedule a directory tree on the observer exactly once."""
        if path in scheduled or not os.path.isdir(path):
            return
        try:
            observer.schedule(handler, path, recursive=True)
            scheduled.add(path)
            print(f"[+] Watching {path}")
        except Exception as exc:
            print(f"[-] Failed to watch {path}: {exc}")

    for path in handler.monitored_paths:
        schedule(path)
    for path in get_removable_drive_paths():
        schedule(path)

    # Poll for USB drives appearing after startup (drive letters are assigned
    # at mount time) and add them to the watch so mass copies to USB produce
    # file_create events for the correlation engine.
    def poll_drives():
        while True:
            time.sleep(5)
            for path in get_removable_drive_paths():
                schedule(path)

    threading.Thread(target=poll_drives, daemon=True).start()
    observer.start()
    return observer
