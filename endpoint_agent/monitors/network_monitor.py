import os
import psutil
from collections import deque


class NetworkMonitor:
    """Outbound-upload monitor with rolling baseline spike detection & process file handle correlation.

    ``psutil.net_io_counters()`` reports the machine's aggregate outbound bytes.
    When a genuine upload spike is detected, the monitor inspects active network-connected
    processes (e.g. browsers, curl, python, powershell, git, cloud clients) and captures
    the open user file handles to identify exactly which file is being uploaded.
    It also captures the remote destination IP/hostname the process is connected to.
    """

    POLL_SECONDS = 30        # how often outbound traffic is sampled
    MIN_UPLOAD_MB = 2.0      # absolute floor: never alarm below this per window
    SPIKE_FACTOR = 2.0       # require the window to be this many x the baseline
    BASELINE_WINDOWS = 5     # how many past windows define "normal"

    def __init__(self, callback):
        self.callback = callback
        self._last_sent = None
        self._history = deque(maxlen=self.BASELINE_WINDOWS)

    @staticmethod
    def _median(values):
        ordered = sorted(values)
        n = len(ordered)
        if n % 2 == 1:
            return ordered[n // 2]
        return (ordered[n // 2 - 1] + ordered[n // 2]) / 2.0

    @staticmethod
    def find_uploading_files():
        """Inspect running processes for network sockets and active open file handles.
        
        Returns list of candidates with file info, process name, PID, and destination IP.
        Filters out system/browser internal files to show only real user documents.
        """
        upload_candidates = []

        # Extensions that are definitely NOT user uploads — OS/browser internals
        ignored_extensions = {
            ".dll", ".sys", ".exe", ".log", ".tmp", ".dat", ".mui", ".pyd",
            ".cat", ".idx", ".tflite", ".crx3", ".pak", ".bin", ".ldb",
            ".lock", ".journal", ".etl", ".ttf", ".otf", ".woff", ".woff2",
            ".nls", ".manifest", ".config", ".pf", ".regtrans-ms",
            "_0", "_1", "_2", "_3",
        }

        # Paths that indicate OS/browser internals — never user-uploaded files
        ignored_paths = [
            "windows\\system32", "windows\\fonts", "windows\\winsxs",
            "windows\\servicing", "windows\\assembly",
            "program files", "program files (x86)",
            "appdata\\local\\temp", "node_modules", "package.json",
            "appdata\\local\\google\\chrome\\user data",
            "appdata\\local\\microsoft\\edge\\user data",
            "appdata\\roaming\\mozilla\\firefox\\profiles",
            "appdata\\local\\packages", "appdata\\local\\microsoft\\windows",
            ".git\\", "__pycache__", ".venv", "site-packages",
        ]

        # Processes that can perform network uploads
        target_procs = [
            "chrome", "msedge", "firefox", "brave", "opera",
            "python", "curl", "wget",
            "powershell", "cmd", "git", "scp", "sftp", "filezilla",
            "dropbox", "onedrive", "googledrive", "icloud",
            "node", "slack", "teams", "telegram", "discord",
            "postman", "insomnia",
        ]

        try:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    pname = (proc.info.get("name") or "").lower()
                    if not any(tp in pname for tp in target_procs):
                        continue

                    p = psutil.Process(proc.info["pid"])

                    # Get destination IPs this process is connected to
                    dest_ips = set()
                    try:
                        conns = p.net_connections(kind='inet')
                        for conn in conns:
                            if conn.status == 'ESTABLISHED' and conn.raddr:
                                remote_ip = conn.raddr.ip
                                # Skip localhost/loopback
                                if not remote_ip.startswith("127.") and remote_ip != "::1":
                                    dest_ips.add(f"{remote_ip}:{conn.raddr.port}")
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                    open_files = p.open_files()
                    for f in open_files:
                        path = getattr(f, "path", None)
                        if not path or not isinstance(path, str):
                            continue
                        ext = os.path.splitext(path)[1].lower()
                        if ext in ignored_extensions:
                            continue
                        path_lower = path.lower()
                        if any(ign in path_lower for ign in ignored_paths):
                            continue

                        fname = os.path.basename(path)
                        folder = os.path.dirname(path)

                        # Try to get file size
                        file_size_str = None
                        try:
                            if os.path.exists(path):
                                fsize = os.path.getsize(path)
                                if fsize >= 1024 * 1024:
                                    file_size_str = f"{fsize / (1024 * 1024):.1f}MB"
                                elif fsize >= 1024:
                                    file_size_str = f"{fsize / 1024:.1f}KB"
                                else:
                                    file_size_str = f"{fsize}B"
                        except (OSError, PermissionError):
                            pass

                        upload_candidates.append({
                            "process_name": proc.info.get("name", "process"),
                            "pid": proc.info["pid"],
                            "filename": fname,
                            "folder": folder,
                            "extension": ext,
                            "path": path,
                            "file_size": file_size_str,
                            "destinations": list(dest_ips)[:3],  # top 3 remote IPs
                        })
                        if len(upload_candidates) >= 5:
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                if len(upload_candidates) >= 5:
                    break
        except Exception:
            pass

        return upload_candidates

    def check_once(self):
        """Sample cumulative bytes_sent and emit only a genuine spike event with correlated file."""
        try:
            counters = psutil.net_io_counters()
        except Exception:
            return  # counters unavailable on this platform — skip quietly

        now_sent = counters.bytes_sent
        if self._last_sent is None:
            self._last_sent = now_sent  # first sample just sets the baseline
            return

        delta_bytes = max(0, now_sent - self._last_sent)
        self._last_sent = now_sent

        delta_mb = delta_bytes / (1024 * 1024)
        # Baseline excludes the current window so a single burst cannot raise it.
        baseline_mb = self._median(self._history) if self._history else 0.0
        self._history.append(delta_mb)

        # Skip until a couple of windows establish what "normal" is.
        if len(self._history) < 2:
            return

        is_spike = (
            delta_mb >= self.MIN_UPLOAD_MB
            and delta_mb >= self.SPIKE_FACTOR * max(baseline_mb, 0.5)
        )
        if not is_spike:
            return

        top_files = self.find_uploading_files()
        filename = None
        folder = None
        extension = None
        process_name = None
        file_size = None
        destination = None

        # Build details text parts
        parts = [f"Network upload spike: {delta_mb:.1f}MB in {self.POLL_SECONDS}s (baseline ~{baseline_mb:.1f}MB)"]

        if top_files:
            cand = top_files[0]
            filename = cand["filename"]
            folder = cand["folder"]
            extension = cand["extension"]
            process_name = cand["process_name"]
            file_size = cand.get("file_size")
            folder_label = os.path.basename(folder) or folder

            if cand.get("destinations"):
                destination = cand["destinations"][0]

            parts = [
                f"Upload {delta_mb:.1f}MB via {process_name}",
                f"File: {filename} ({file_size or 'unknown size'}) in {folder_label}",
            ]
            if destination:
                parts.append(f"Destination: {destination}")

        details_text = " | ".join(parts)

        self.callback({
            "event_type": "network_upload",
            "network_upload": f"{delta_mb:.1f}MB",
            "filename": filename,
            "folder": folder,
            "extension": extension,
            "size": file_size,
            "details": details_text,
        })
