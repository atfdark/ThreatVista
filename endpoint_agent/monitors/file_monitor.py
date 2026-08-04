import os
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileDeletedEvent, FileModifiedEvent, FileMovedEvent

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
    for path in handler.monitored_paths:
        if os.path.exists(path):
            observer.schedule(handler, path, recursive=True)
    observer.start()
    return observer
