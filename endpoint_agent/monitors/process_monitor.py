import psutil
from datetime import datetime

class ProcessMonitor:
    def __init__(self, callback):
        self.callback = callback
        self._known_pids = set()
        self._update_known()

    def _update_known(self):
        self._known_pids = {p.pid for p in psutil.process_iter(['pid'])}

    def check_once(self):
        current_pids = {p.pid for p in psutil.process_iter(['pid'])}
        new_pids = current_pids - self._known_pids

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                self.callback({
                    "event_type": "process_start",
                    "details": f"New process started: {proc.name()} (PID: {pid})"
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        closed_pids = self._known_pids - current_pids
        for pid in closed_pids:
            self.callback({
                "event_type": "process_stop",
                "details": f"Process terminated: PID {pid}"
            })

        self._known_pids = current_pids
