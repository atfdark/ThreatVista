import pythoncom
import wmi
from datetime import datetime

class USBMonitor:
    def __init__(self, callback):
        self.callback = callback
        self._c = None
        self._watcher = None

    def start(self):
        try:
            pythoncom.CoInitialize()
            self._c = wmi.WMI()
            self._watcher = self._c.Win32_DeviceChangeEvent.watch_for()
            return True
        except Exception as e:
            print(f"USB monitor init error: {e}")
            return False

    def check_once(self):
        try:
            if not self._c:
                return
            for disk in self._c.Win32_LogicalDisk(DriveType=2):
                self.callback({
                    "event_type": "usb_insert",
                    "usb_status": f"{disk.Caption} - {disk.VolumeName or 'No Label'} ({self._format_size(disk.Size)})",
                    "details": f"USB drive {disk.Caption} detected"
                })
        except Exception as e:
            print(f"USB check error: {e}")

    def _format_size(self, size_bytes):
        try:
            size = int(size_bytes) if size_bytes else 0
            return f"{size / (1024**3):.1f}GB"
        except Exception:
            return "Unknown"

    def stop(self):
        try:
            if self._watcher:
                self._watcher = None
            if self._c:
                self._c = None
            pythoncom.CoUninitialize()
        except Exception:
            pass
