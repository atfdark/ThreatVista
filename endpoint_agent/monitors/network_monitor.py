import psutil


class NetworkMonitor:
    """Machine-wide outbound-upload monitor.

    Windows (psutil) does not expose per-process network byte counters, so this
    tracks the machine's total outbound traffic via ``psutil.net_io_counters()``
    and emits a ``network_upload`` event whenever uploads in the poll window
    exceed ``MIN_UPLOAD_MB``. On a single-user employee laptop that is
    effectively the employee's own upload volume, which is what the risk engine's
    network rules consume (e.g. >100MB elevated, >500MB spike, night uploads).
    """

    POLL_SECONDS = 60        # how often outbound traffic is sampled
    MIN_UPLOAD_MB = 5.0      # emit only when a window has at least this much outbound

    def __init__(self, callback):
        self.callback = callback
        self._last_sent = None

    def check_once(self):
        """Sample cumulative bytes_sent and emit an event when the delta is big."""
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
        if delta_mb >= self.MIN_UPLOAD_MB:
            self.callback({
                "event_type": "network_upload",
                "network_upload": f"{delta_mb:.1f}MB",
                "details": f"Network upload {delta_mb:.1f}MB in the last {self.POLL_SECONDS}s",
            })
