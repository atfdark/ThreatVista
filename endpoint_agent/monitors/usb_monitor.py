import ctypes
import threading
import time


class USBMonitor:
    """USB insert/remove monitor (polling, no WMI dependency).

    The old implementation subscribed to WMI ``Win32_LogicalDisk`` instance
    events, which are flaky on many Windows builds (some USB sticks only appear
    as ``Win32_DiskDrive`` or need a ``Win32_VolumeChangeEvent`` subscription),
    so drives frequently went undetected.

    This version polls the drive letters every ``POLL_SECONDS`` via the Win32
    API (``GetLogicalDrives`` + ``GetDriveTypeW``) and diffs the removable-drive
    set: a new letter is a ``usb_insert``, a vanished letter is a ``usb_remove``.
    Drives already connected at startup form the baseline and are NOT reported,
    so the SOC feed never spams the pre-existing stick.

    On non-Windows the scan returns empty and the monitor is a harmless no-op.
    """

    POLL_SECONDS = 3
    DRIVE_REMOVABLE = 2  # DRIVE_REMOVABLE

    def __init__(self, callback):
        self.callback = callback
        self._running = False
        self._thread = None
        self._known = {}

    def start(self):
        """Start the polling thread. Always succeeds (no optional deps)."""
        self._running = True
        self._known = self._scan()  # baseline — already-connected drives are skipped
        self._thread = threading.Thread(target=self._loop, name="usb-poll", daemon=True)
        self._thread.start()
        print(f"[+] USB monitor started (polling every {self.POLL_SECONDS}s)")
        return True

    def _scan(self):
        """Return {drive_letter: description} for currently-connected removable drives."""
        drives = {}
        try:
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if bitmask & (1 << i):
                    letter = chr(ord("A") + i)
                    root = f"{letter}:\\"
                    if ctypes.windll.kernel32.GetDriveTypeW(root) == self.DRIVE_REMOVABLE:
                        drives[letter] = self._describe(root)
        except Exception as exc:
            print(f"[-] USB scan error: {exc}")
        return drives

    def _describe(self, root):
        label = self._volume_label(root)
        size = self._volume_size(root)
        return f"{root} - {label} ({size})"

    def _loop(self):
        while self._running:
            time.sleep(self.POLL_SECONDS)
            try:
                current = self._scan()
                for letter in current:
                    if letter not in self._known:
                        self._emit("insert", letter, current[letter])
                for letter in self._known:
                    if letter not in current:
                        self._emit("remove", letter, self._known[letter])
                self._known = current
            except Exception as exc:
                print(f"[-] USB poll error: {exc}")

    def _emit(self, action, letter, description):
        self.callback({
            "event_type": f"usb_{action}",  # usb_insert | usb_remove
            "usb_status": description,
            "details": f"USB drive {letter} {'inserted' if action == 'insert' else 'removed'}",
        })

    def _volume_label(self, root):
        try:
            import win32api
            return win32api.GetVolumeInformation(root)[0]
        except Exception:
            return "No Label"

    def _volume_size(self, root):
        try:
            free = ctypes.c_ulonglong()
            total = ctypes.c_ulonglong()
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                root, None, ctypes.byref(total), ctypes.byref(free)
            )
            gb = total.value / (1024 ** 3)
            return f"{gb:.1f}GB"
        except Exception:
            return "Unknown"

    def stop(self):
        """Signal the polling thread to exit and wait for it."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        self._thread = None
