"""
Thread-safe event batcher for the endpoint agent.

Collects telemetry events in a small buffer and flushes them as one batch via a
background thread — either when ~``flush_interval`` seconds have elapsed since
the first buffered event, or when ``max_events`` have accumulated. This turns a
150-file burst into 1-2 HTTP requests instead of 150, while still feeling
near-real-time for sparse events.
"""
import threading
import time


class EventBatcher:
    def __init__(self, flush_callback, max_events=100, flush_interval=1.0):
        self._flush_callback = flush_callback
        self._max_events = max_events
        self._flush_interval = flush_interval

        self._lock = threading.Lock()
        self._buffer = []
        self._first_event_time = None

        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def add(self, event):
        """Queue one event. Safe to call from any monitor thread."""
        with self._lock:
            if not self._buffer:
                self._first_event_time = time.time()
            self._buffer.append(event)
            if len(self._buffer) >= self._max_events:
                self._wake.set()

    def flush(self):
        """Immediately send whatever is buffered (used on shutdown)."""
        batch = self._take_batch()
        if batch:
            self._send(batch)

    def stop(self):
        """Stop the flusher thread, sending any remaining events first."""
        self._stop.set()
        self._wake.set()
        self.flush()
        self._thread.join(timeout=5)

    def _take_batch(self):
        with self._lock:
            if not self._buffer:
                return []
            batch = self._buffer
            self._buffer = []
            self._first_event_time = None
        return batch

    def _run(self):
        while not self._stop.is_set():
            # Wake on a short tick so a sparse batch still flushes ~1s after its
            # first event. The 0.2s granularity keeps the ~1s cadence snappy.
            self._wake.wait(timeout=0.2)
            self._wake.clear()
            with self._lock:
                if not self._buffer:
                    continue
                elapsed = time.time() - self._first_event_time
                if len(self._buffer) < self._max_events and elapsed < self._flush_interval:
                    continue
                batch = self._buffer
                self._buffer = []
                self._first_event_time = None
            if batch:
                self._send(batch)

    def _send(self, batch):
        try:
            self._flush_callback(batch)
        except Exception as exc:
            print(f"[batch] send failed for {len(batch)} events: {exc}")
