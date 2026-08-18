import ctypes
import os
import re
import threading
import time


class USBMonitor:
    """Real-time USB storage device monitor with rich hardware metadata.

    Detects removable drive connections/disconnections via the Win32 API
    (GetLogicalDrives + GetDriveTypeW + GetVolumeInformationW + GetDiskFreeSpaceExW)
    and enriches events with hardware metadata (Vendor ID, Product ID, Hardware
    Serial Number, Model Name, Volume Label, File System, Total Size) extracted
    from Windows registry (USBSTOR) and WMI when available.

    Drives connected at agent startup establish the baseline and are skipped,
    preventing duplicate alert spam on restart.
    """

    POLL_SECONDS = 2
    DRIVE_REMOVABLE = 2  # DRIVE_REMOVABLE

    def __init__(self, callback):
        self.callback = callback
        self._running = False
        self._thread = None
        self._known = {}
        self._last_emitted = {}  # (action, letter) -> timestamp

    def start(self):
        """Start the polling thread. Returns True if successfully initialized."""
        self._running = True
        self._known = self._scan()  # baseline — already-connected drives are skipped
        self._thread = threading.Thread(target=self._loop, name="usb-poll", daemon=True)
        self._thread.start()
        print(f"[+] Real-time USB monitor started (polling every {self.POLL_SECONDS}s with rich hardware telemetry)")
        return True

    def _scan(self):
        """Return {drive_letter: device_info_dict} for currently-connected removable drives."""
        drives = {}
        try:
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if bitmask & (1 << i):
                    letter = chr(ord("A") + i)
                    root = f"{letter}:\\"
                    if ctypes.windll.kernel32.GetDriveTypeW(root) == self.DRIVE_REMOVABLE:
                        drives[letter] = self._inspect_drive(letter, root)
        except Exception as exc:
            print(f"[-] USB scan error: {exc}")
        return drives

    def _inspect_drive(self, letter: str, root: str) -> dict:
        """Collect deep hardware, volume, and filesystem metadata for a removable drive."""
        vol_info = self._get_volume_info(root)
        total_size, free_size = self._get_disk_sizes(root)
        hw_info = self._get_hardware_info(letter)

        volume_name = vol_info.get("volume_name") or "Removable Disk"
        file_system = vol_info.get("file_system") or "FAT32"
        serial_number = hw_info.get("serial_number") or vol_info.get("serial_number") or "N/A"
        device_name = hw_info.get("device_name") or (f"{volume_name} ({letter}:)" if volume_name != "Removable Disk" else f"USB Storage Device ({letter}:)")
        vendor_id = hw_info.get("vendor_id") or "Generic"
        product_id = hw_info.get("product_id") or "USB Disk"

        desc = f"{device_name} - {volume_name} [{letter}:] ({total_size}, {file_system})"

        return {
            "drive_letter": f"{letter}:",
            "root_path": root,
            "device_name": device_name,
            "vendor_id": vendor_id,
            "product_id": product_id,
            "serial_number": serial_number,
            "volume_name": volume_name,
            "total_size": total_size,
            "free_size": free_size,
            "file_system": file_system,
            "description": desc,
        }

    def _get_volume_info(self, root: str) -> dict:
        """Query volume label, volume serial number, and filesystem name via Win32 API."""
        try:
            vol_buf = ctypes.create_unicode_buffer(260)
            fs_buf = ctypes.create_unicode_buffer(260)
            serial = ctypes.c_ulong()
            max_comp = ctypes.c_ulong()
            flags = ctypes.c_ulong()

            res = ctypes.windll.kernel32.GetVolumeInformationW(
                root,
                vol_buf,
                260,
                ctypes.byref(serial),
                ctypes.byref(max_comp),
                ctypes.byref(flags),
                fs_buf,
                260,
            )
            if res:
                v_name = vol_buf.value.strip() or "Removable Disk"
                fs_name = fs_buf.value.strip() or "FAT32"
                sn_hex = f"{serial.value:08X}"
                sn_formatted = f"{sn_hex[:4]}-{sn_hex[4:]}" if len(sn_hex) == 8 else sn_hex
                return {
                    "volume_name": v_name,
                    "serial_number": sn_formatted,
                    "file_system": fs_name,
                }
        except Exception:
            pass

        return {
            "volume_name": "Removable Disk",
            "serial_number": "N/A",
            "file_system": "FAT32",
        }

    def _get_disk_sizes(self, root: str) -> tuple:
        """Query total and free capacity formatted as human-readable GB/MB."""
        try:
            free_bytes = ctypes.c_ulonglong()
            total_bytes = ctypes.c_ulonglong()
            total_free_bytes = ctypes.c_ulonglong()
            res = ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                root,
                ctypes.byref(free_bytes),
                ctypes.byref(total_bytes),
                ctypes.byref(total_free_bytes),
            )
            if res and total_bytes.value > 0:
                tot_gb = total_bytes.value / (1024 ** 3)
                free_gb = free_bytes.value / (1024 ** 3)
                tot_str = f"{tot_gb:.1f}GB" if tot_gb >= 1.0 else f"{total_bytes.value / (1024 ** 2):.0f}MB"
                free_str = f"{free_gb:.1f}GB" if free_gb >= 1.0 else f"{free_bytes.value / (1024 ** 2):.0f}MB"
                return tot_str, free_str
        except Exception:
            pass
        return "Unknown", "Unknown"

    def _get_hardware_info(self, drive_letter: str) -> dict:
        """Enrich with Vendor ID, Product ID, Serial Number, and Model from USBSTOR/WMI."""
        info = {
            "device_name": None,
            "vendor_id": None,
            "product_id": None,
            "serial_number": None,
        }

        # 1. Try WMI query via win32com if available
        try:
            import win32com.client
            wmi = win32com.client.GetObject("winmgmts:")
            target = f"{drive_letter}:"
            # Trace LogicalDisk -> Partition -> DiskDrive
            parts = wmi.ExecQuery(
                f"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{target}'}} WHERE AssocClass = Win32_LogicalDiskToPartition"
            )
            for part in parts:
                drives = wmi.ExecQuery(
                    f"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{part.DeviceID}'}} WHERE AssocClass = Win32_DiskDriveToPartition"
                )
                for drive in drives:
                    model = getattr(drive, "Model", "")
                    pnp_id = getattr(drive, "PNPDeviceID", "")
                    sn = getattr(drive, "SerialNumber", "")
                    if model:
                        info["device_name"] = model.strip()
                    if sn and sn.strip():
                        info["serial_number"] = sn.strip()
                    # Parse VID & PID from PNPDeviceID
                    vid_match = re.search(r"VID_([0-9A-Fa-f]{4})", pnp_id)
                    if vid_match:
                        info["vendor_id"] = vid_match.group(1).upper()
                    pid_match = re.search(r"PID_([0-9A-Fa-f]{4})", pnp_id)
                    if pid_match:
                        info["product_id"] = pid_match.group(1).upper()

                    # Also handle USBSTOR format: USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\0401...
                    if not info["vendor_id"]:
                        ven_match = re.search(r"VEN_([A-Za-z0-9_\-\.]+)", pnp_id)
                        if ven_match:
                            info["vendor_id"] = ven_match.group(1).replace("_", " ").strip()
                    if not info["product_id"]:
                        prod_match = re.search(r"PROD_([A-Za-z0-9_\-\.]+)", pnp_id)
                        if prod_match:
                            info["product_id"] = prod_match.group(1).replace("_", " ").strip()
                    if info["device_name"]:
                        return info
        except Exception:
            pass

        # 2. Fallback to Windows Registry (USBSTOR)
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR")
            num_keys = winreg.QueryInfoKey(key)[0]
            if num_keys > 0:
                # Use the most recent / first active USBSTOR key
                for i in range(num_keys - 1, -1, -1):
                    dev_type = winreg.EnumKey(key, i)
                    dev_key = winreg.OpenKey(key, dev_type)
                    num_devs = winreg.QueryInfoKey(dev_key)[0]
                    for j in range(num_devs):
                        instance_id = winreg.EnumKey(dev_key, j)
                        inst_key = winreg.OpenKey(dev_key, instance_id)
                        friendly_name = ""
                        try:
                            friendly_name, _ = winreg.QueryValueEx(inst_key, "FriendlyName")
                        except Exception:
                            pass

                        ven_m = re.search(r"Ven_([A-Za-z0-9_\-]+)", dev_type, re.IGNORECASE)
                        prod_m = re.search(r"Prod_([A-Za-z0-9_\-]+)", dev_type, re.IGNORECASE)

                        info["device_name"] = friendly_name or dev_type.replace("Disk&", "").replace("_", " ")
                        info["vendor_id"] = ven_m.group(1).replace("_", " ") if ven_m else "USB"
                        info["product_id"] = prod_m.group(1).replace("_", " ") if prod_m else "Storage"
                        info["serial_number"] = instance_id.split("&")[0] if "&" in instance_id else instance_id
                        return info
        except Exception:
            pass

        return info

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

    def _emit(self, action: str, letter: str, info: dict):
        now = time.time()
        key = (action, letter)
        last_time = self._last_emitted.get(key, 0)
        if now - last_time < 3.0:
            return  # Ignore rapid hardware debounce
        self._last_emitted[key] = now

        device_name = info.get("device_name") or f"USB Storage Device ({letter}:)"
        vid = info.get("vendor_id") or "Generic"
        pid = info.get("product_id") or "Disk"
        serial = info.get("serial_number") or "N/A"
        vol_name = info.get("volume_name") or "Removable Disk"
        size = info.get("total_size") or "Unknown"
        fs = info.get("file_system") or "FAT32"

        action_title = "connected" if action == "insert" else "disconnected"
        details_text = (
            f"USB storage device {action_title}: {device_name} "
            f"[{vol_name} at drive {letter}:, Capacity: {size}, FS: {fs}, VID: {vid}, PID: {pid}, SN: {serial}]"
        )

        event_payload = {
            "event_type": f"usb_{action}",  # usb_insert | usb_remove
            "usb_status": info.get("description") or f"{device_name} ({letter}:)",
            "details": details_text,
            "device_name": device_name,
            "vendor_id": vid,
            "product_id": pid,
            "serial_number": serial,
            "drive_letter": f"{letter}:",
            "volume_name": vol_name,
            "size": size,
            "file_system": fs,
            "urgent": True,  # Signals the batcher to flush immediately for real-time alerts
        }

        print(f"[!] Real-Time USB Event: {action.upper()} detected on {letter}: -> {device_name} (SN: {serial})")
        self.callback(event_payload)

    def stop(self):
        """Signal the polling thread to exit and wait for it."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        self._thread = None

