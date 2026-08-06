import threading

# Optional Windows-only dependencies. Import at module level so the agent can
# degrade gracefully on non-Windows machines instead of crashing at startup.
try:
    import pythoncom
    import wmi
except ImportError:
    pythoncom = None
    wmi = None


class USBMonitor:
    """Event-driven USB insert/remove monitor.

    Instead of polling for drives every few seconds (which either spams
    ``usb_insert`` for already-connected drives or, when never scheduled,
    reports nothing at all), two background daemon threads subscribe to WMI
    *instance* events on ``Win32_LogicalDisk``:

      Thread                WMI event              Fires when
      --------------------  ---------------------- -------------------------
      usb-insert-watcher    __InstanceCreationEvent  a drive is plugged in
      usb-remove-watcher    __InstanceDeletionEvent  a drive is ejected/pulled

    WMI blocks until the OS fires the event, so there is zero CPU cost while
    idle. Each watcher uses a 1-second timeout so ``stop()`` can exit cleanly.

    The interface (``start()`` / ``stop()``) is identical to the old version,
    so the endpoint agent needs no changes.
    """

    # Only removable media (pen drives / card readers). Skips optical (5),
    # local fixed (3) and network (4) disks so CD or drive-map activity doesn't
    # spam the SOC feed.
    REMOVABLE_DRIVE_TYPE = 2

    def __init__(self, callback):
        self.callback = callback
        self._running = False
        self._threads = []

    def start(self):
        """Start the two WMI watcher threads.

        Returns True when the watchers are running, False (after printing a
        warning) when pywin32/WMI isn't available so the agent can continue
        without USB monitoring.
        """
        if wmi is None or pythoncom is None:
            print("[-] USB monitor not available: pywin32/WMI is not installed")
            return False

        self._running = True
        for notification_type, action in (("creation", "insert"), ("deletion", "remove")):
            thread = threading.Thread(
                target=self._watcher_loop,
                args=(notification_type, action),
                name=f"usb-{action}-watcher",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

        print(f"[+] USB monitor started ({len(self._threads)} WMI watchers)")
        return True

    def _watcher_loop(self, notification_type, action):
        """Block on WMI events for one class of drive lifecycle event."""
        pythoncom.CoInitialize()
        try:
            conn = wmi.WMI()
            watcher = conn.Win32_LogicalDisk.watch_for(notification_type, delay_secs=1)
            while self._running:
                try:
                    # 1-second timeout keeps this loop responsive to stop().
                    event = watcher(1000)
                except wmi.x_wmi_timed_out:
                    pythoncom.PumpWaitingMessages()
                    continue
                except Exception as exc:
                    print(f"[-] USB watcher ({action}) error: {exc}")
                    break
                if event is not None:
                    self._emit(event, action)
        except Exception as exc:
            print(f"[-] USB monitor ({action}) init error: {exc}")
        finally:
            pythoncom.CoUninitialize()

    def _emit(self, event, action):
        """Convert a Win32_LogicalDisk event into a usb_insert/usb_remove payload."""
        try:
            # wmi's watcher proxies the created/deleted disk directly, but a
            # couple of versions keep it under TargetInstance — handle both.
            disk = event
            target = getattr(event, "TargetInstance", None)
            if target is not None and getattr(target, "Caption", None):
                disk = target

            drive_type = getattr(disk, "DriveType", None)
            if drive_type is not None and drive_type != self.REMOVABLE_DRIVE_TYPE:
                return  # not a pen drive (e.g. CD / local / network mount)

            caption = getattr(disk, "Caption", None) or "USB"
            volume = getattr(disk, "VolumeName", None) or "No Label"
            size = self._format_size(getattr(disk, "Size", None))

            self.callback({
                "event_type": f"usb_{action}",  # usb_insert | usb_remove
                "usb_status": f"{caption} - {volume} ({size})",
                "details": f"USB drive {caption} {'inserted' if action == 'insert' else 'removed'}",
            })
        except Exception as exc:
            print(f"[-] USB event emit error: {exc}")

    def _format_size(self, size_bytes):
        try:
            size = int(size_bytes) if size_bytes else 0
            return f"{size / (1024**3):.1f}GB"
        except Exception:
            return "Unknown"

    def stop(self):
        """Signal both watcher threads to exit and wait for them."""
        self._running = False
        for thread in self._threads:
            thread.join(timeout=2)
        self._threads = []
