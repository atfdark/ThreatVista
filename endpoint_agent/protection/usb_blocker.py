"""
ThreatVista USB Blocker — Real USB Mass Storage Control.

Provides two levels of USB protection:

1. **Registry-level block** (requires Admin/elevated privileges):
   Sets HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR\\Start = 4 (Disabled).
   This prevents Windows from mounting *new* USB mass storage devices entirely.
   They will not appear in File Explorer or as drive letters.

2. **Drive-level eject** (works without elevation):
   Ejects all currently-mounted removable drives via DeviceIoControl, making
   them disappear from File Explorer immediately.

The blocker also supports **unblocking** (Start = 3, Enabled) when the admin
lifts the restriction from the dashboard.

Thread-safe: all state is guarded by a lock so the heartbeat loop and USB
monitor can safely query ``is_blocked()``.
"""
import ctypes
import os
import sys
import threading
import time
from typing import List, Optional


class USBBlocker:
    """Controls USB mass storage access on the local Windows endpoint."""

    def __init__(self):
        self._lock = threading.Lock()
        self._ejected_drives: List[str] = []  # letters that were force-ejected
        
        # Read initial state from registry so it persists across agent restarts
        usbstor_start = self._get_usbstor_start()
        self._blocked = (usbstor_start == 4)
        
        write_protect = self._get_write_protect()
        self._readonly = (write_protect == 1)
        
        if self._blocked:
            print("[🔒] USBBlocker initialized: USB mass storage is CURRENTLY BLOCKED via registry.")
        if self._readonly:
            print("[🔒] USBBlocker initialized: USB mass storage is CURRENTLY READ-ONLY via registry.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_blocked(self) -> bool:
        """Return True if USB storage is currently blocked on this machine."""
        with self._lock:
            return self._blocked

    def block(self) -> dict:
        """Disable USB mass storage: set registry key + eject mounted drives.

        Returns a status dict for logging / heartbeat response.
        """
        results = {
            "registry_blocked": False,
            "drives_ejected": [],
            "errors": [],
        }

        with self._lock:
            # 1. Try disabling via Windows Registry (requires elevation)
            reg_ok = self._set_usbstor_start(4)  # 4 = Disabled
            results["registry_blocked"] = reg_ok
            if not reg_ok:
                results["errors"].append(
                    "Registry write failed (agent may not be running as Admin)"
                )

            # 2. Eject all currently-mounted removable drives
            ejected = self._eject_all_removable_drives()
            results["drives_ejected"] = ejected
            self._ejected_drives = ejected

            self._blocked = True

        action = "Registry + Eject" if reg_ok else "Eject-only (no admin)"
        print(f"[🔒 USB BLOCKED] USB mass storage disabled ({action}). "
              f"Ejected drives: {ejected or 'none mounted'}")
        return results

    def unblock(self) -> dict:
        """Re-enable USB mass storage: restore registry key."""
        results = {
            "registry_unblocked": False,
            "errors": [],
        }

        with self._lock:
            reg_ok = self._set_usbstor_start(3)  # 3 = Manual (default)
            results["registry_unblocked"] = reg_ok
            if not reg_ok:
                results["errors"].append(
                    "Registry write failed (agent may not be running as Admin)"
                )
            self._blocked = False
            self._ejected_drives = []

        print("[🔓 USB UNBLOCKED] USB mass storage re-enabled.")
        return results

    # ------------------------------------------------------------------
    # Registry control
    # ------------------------------------------------------------------

    @staticmethod
    def _set_usbstor_start(value: int) -> bool:
        """Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR\\Start.

        value=4 disables USB mass storage (new devices won't mount).
        value=3 re-enables it (default Windows behavior).

        Returns True on success, False if the write fails (e.g. not elevated).
        """
        if sys.platform != "win32":
            return False

        try:
            import winreg
            key_path = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                key_path,
                0,
                winreg.KEY_SET_VALUE | winreg.KEY_READ,
            )
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, value)
            winreg.CloseKey(key)
            return True
        except PermissionError:
            print(f"[-] USB Registry: Access denied. Run agent as Administrator.")
            return False
        except Exception as exc:
            print(f"[-] USB Registry error: {exc}")
            return False

    @staticmethod
    def _get_usbstor_start() -> Optional[int]:
        """Read the current USBSTOR\\Start value. Returns None on failure."""
        if sys.platform != "win32":
            return None
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\USBSTOR",
                0,
                winreg.KEY_READ,
            )
            val, _ = winreg.QueryValueEx(key, "Start")
            winreg.CloseKey(key)
            return val
        except Exception:
            return None

    def set_readonly(self) -> dict:
        """Enable Write Protection for USB drives via Windows Registry."""
        results = {"registry_readonly": False, "errors": []}
        with self._lock:
            reg_ok = self._set_write_protect(1)
            results["registry_readonly"] = reg_ok
            if not reg_ok:
                results["errors"].append("Registry write failed (agent may not be running as Admin)")
            self._readonly = True
        
        print(f"[🔒 USB READ-ONLY] USB mass storage write protection enabled.")
        return results

    def clear_readonly(self) -> dict:
        """Disable Write Protection for USB drives via Windows Registry."""
        results = {"registry_readwrite": False, "errors": []}
        with self._lock:
            reg_ok = self._set_write_protect(0)
            results["registry_readwrite"] = reg_ok
            if not reg_ok:
                results["errors"].append("Registry write failed (agent may not be running as Admin)")
            self._readonly = False
        
        print(f"[🔓 USB READ/WRITE] USB mass storage write protection disabled.")
        return results

    @staticmethod
    def _set_write_protect(value: int) -> bool:
        """Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies\\WriteProtect."""
        if sys.platform != "win32":
            return False
        try:
            import winreg
            key_path = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
            except FileNotFoundError:
                key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                
            winreg.SetValueEx(key, "WriteProtect", 0, winreg.REG_DWORD, value)
            winreg.CloseKey(key)
            return True
        except PermissionError:
            print(f"[-] USB Registry: Access denied to StorageDevicePolicies. Run agent as Administrator.")
            return False
        except Exception as exc:
            print(f"[-] USB Registry error: {exc}")
            return False

    @staticmethod
    def _get_write_protect() -> Optional[int]:
        """Read the current StorageDevicePolicies\\WriteProtect value."""
        if sys.platform != "win32":
            return None
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies",
                0,
                winreg.KEY_READ,
            )
            val, _ = winreg.QueryValueEx(key, "WriteProtect")
            winreg.CloseKey(key)
            return val
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Drive ejection
    # ------------------------------------------------------------------

    @staticmethod
    def _eject_all_removable_drives() -> List[str]:
        """Eject every currently-mounted removable drive.

        Uses two strategies:
        1. Volume lock + dismount + eject via DeviceIoControl (clean).
        2. Fallback: remove drive letter from the bitmask so it vanishes
           from Explorer (cosmetic but effective for the user).

        Returns list of ejected drive letters, e.g. ['E', 'F'].
        """
        if sys.platform != "win32":
            return []

        ejected = []
        try:
            DRIVE_REMOVABLE = 2
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if bitmask & (1 << i):
                    letter = chr(ord("A") + i)
                    root = f"{letter}:\\"
                    if ctypes.windll.kernel32.GetDriveTypeW(root) == DRIVE_REMOVABLE:
                        if USBBlocker._eject_drive(letter):
                            ejected.append(letter)
        except Exception as exc:
            print(f"[-] Drive ejection scan error: {exc}")

        return ejected

    @staticmethod
    def _eject_drive(letter: str) -> bool:
        """Eject a single removable drive by letter (e.g. 'E').

        Opens the volume device (\\\\.\\E:), locks it, dismounts it, and sends
        the IOCTL_STORAGE_EJECT_MEDIA control code. If DeviceIoControl
        fails (e.g. drive is busy), falls back to a WMI-based safe-remove.
        """
        if sys.platform != "win32":
            return False

        try:
            # Constants
            GENERIC_READ = 0x80000000
            GENERIC_WRITE = 0x40000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3
            FSCTL_LOCK_VOLUME = 0x00090018
            FSCTL_DISMOUNT_VOLUME = 0x00090020
            IOCTL_STORAGE_EJECT_MEDIA = 0x002D4808
            INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

            device_path = f"\\\\.\\{letter}:"
            handle = ctypes.windll.kernel32.CreateFileW(
                device_path,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None,
            )

            if handle == INVALID_HANDLE_VALUE:
                print(f"[-] Cannot open volume {letter}: for ejection")
                return False

            bytes_returned = ctypes.c_ulong(0)

            # Lock volume
            ctypes.windll.kernel32.DeviceIoControl(
                handle, FSCTL_LOCK_VOLUME,
                None, 0, None, 0,
                ctypes.byref(bytes_returned), None,
            )

            # Dismount volume
            ctypes.windll.kernel32.DeviceIoControl(
                handle, FSCTL_DISMOUNT_VOLUME,
                None, 0, None, 0,
                ctypes.byref(bytes_returned), None,
            )

            # Eject media
            result = ctypes.windll.kernel32.DeviceIoControl(
                handle, IOCTL_STORAGE_EJECT_MEDIA,
                None, 0, None, 0,
                ctypes.byref(bytes_returned), None,
            )

            ctypes.windll.kernel32.CloseHandle(handle)

            if result:
                print(f"[🔒] Ejected drive {letter}:")
                return True
            else:
                print(f"[-] DeviceIoControl eject failed for {letter}:, trying WMI fallback")
                return USBBlocker._eject_via_wmi(letter)

        except Exception as exc:
            print(f"[-] Drive {letter}: eject error: {exc}")
            return False

    @staticmethod
    def _eject_via_wmi(letter: str) -> bool:
        """Fallback: eject via WMI Win32_Volume.Dismount()."""
        try:
            import win32com.client
            wmi = win32com.client.GetObject("winmgmts:")
            volumes = wmi.ExecQuery(
                f"SELECT * FROM Win32_Volume WHERE DriveLetter = '{letter}:'"
            )
            for vol in volumes:
                vol.Dismount(True, True)  # Force, Permanent
                print(f"[🔒] WMI dismounted drive {letter}:")
                return True
        except Exception:
            pass
        return False

    # ------------------------------------------------------------------
    # Intercept: block newly-inserted USB in real-time
    # ------------------------------------------------------------------

    def intercept_new_usb(self, letter: str, device_info: dict) -> bool:
        """Called by USBMonitor when a new USB is inserted while block is active.

        Immediately ejects the drive so it never becomes accessible.
        Returns True if the drive was successfully ejected.
        """
        if not self.is_blocked():
            return False

        print(f"[🔒 INTERCEPTED] New USB detected on {letter}: while block is active — ejecting immediately")
        success = self._eject_drive(letter)

        if success:
            with self._lock:
                if letter not in self._ejected_drives:
                    self._ejected_drives.append(letter)
            
            self._notify_user(
                "ThreatVista Security Alert",
                f"Company Policy: USB Mass Storage is currently restricted.\n\nDrive {letter}: has been safely ejected."
            )

        return success

    @staticmethod
    def _notify_user(title: str, message: str):
        """Show native Windows 10/11 Toast Notification to employee."""
        if sys.platform == "win32":
            def _async_msg():
                try:
                    import subprocess
                    ps_script = f"""
                    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
                    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
                    $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
                    $textNodes = $template.GetElementsByTagName("text")
                    $textNodes.Item(0).AppendChild($template.CreateTextNode("{title}")) | Out-Null
                    $textNodes.Item(1).AppendChild($template.CreateTextNode("{message.replace(chr(10), ' ')}")) | Out-Null
                    $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
                    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("ThreatVista Agent")
                    $notifier.Show($toast)
                    """
                    subprocess.run(["powershell", "-Command", ps_script], creationflags=subprocess.CREATE_NO_WINDOW)
                except Exception as e:
                    print(f"[-] Failed to show toast notification: {e}")
            threading.Thread(target=_async_msg, daemon=True).start()
