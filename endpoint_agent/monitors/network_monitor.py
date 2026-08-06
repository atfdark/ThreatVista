import psutil
from collections import deque


class NetworkMonitor:
    """Outbound-upload monitor with a rolling baseline (spike detection).

    ``psutil.net_io_counters()`` reports the WHOLE machine's outbound bytes —
    browser, OneDrive, Windows Update, Teams. A fixed threshold therefore
    misfires constantly on a normal laptop: the user sees a fake
    "Network upload 6.4MB" threat even when they uploaded nothing. So this
    monitor does not just check an absolute number; it compares each 60s window
    against the machine's own recent baseline and only emits a ``network_upload``
    event when the window is BOTH above an absolute floor (``MIN_UPLOAD_MB``)
    AND a clear spike (``SPIKE_FACTOR`` x the rolling median). Routine cloud
    sync becomes part of the baseline instead of an alert; a real exfiltration
    burst still fires.

    The first sample only establishes the baseline; the first couple of windows
    are skipped so the median has real data to compare against.
    """

    POLL_SECONDS = 60        # how often outbound traffic is sampled
    MIN_UPLOAD_MB = 50.0     # absolute floor: never alarm below this per window
    SPIKE_FACTOR = 3.0       # require the window to be this many x the baseline
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

    def check_once(self):
        """Sample cumulative bytes_sent and emit only a genuine spike event."""
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
            and delta_mb >= self.SPIKE_FACTOR * max(baseline_mb, 1.0)
        )
        if not is_spike:
            return

        self.callback({
            "event_type": "network_upload",
            "network_upload": f"{delta_mb:.1f}MB",
            "details": (
                f"Network upload spike of {delta_mb:.1f}MB in the last "
                f"{self.POLL_SECONDS}s (baseline ~{baseline_mb:.1f}MB)"
            ),
        })
