"""
Thread-safe event batcher for the endpoint agent.

Collects telemetry events in a small buffer and flushes them as one batch via a
background thread — either when ~``flush_interval`` seconds have elapsed since
the first buffered event, or when ``max_events`` have accumulated. This turns a
150-file burst into 1 HTTP request instead of 150, while still feeling
near-real-time for sparse events.

TUNING: max_events=500 ensures a 150-file burst goes as ONE batch (not split
across two). flush_interval=0.5s keeps sparse events snappy.
"""
import threading
import time


class EventBatcher:
    def __init__(self, flush_callback, max_events=500, flush_interval=0.5):
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
        is_urgent = bool(event.get("urgent") or event.get("event_type") in ("usb_insert", "usb_remove"))
        with self._lock:
            if not self._buffer:
                self._first_event_time = time.time()
            self._buffer.append(event)
            if is_urgent or len(self._buffer) >= self._max_events:
                self._wake.set()

    def flush(self):
        """Immediately send whatever is buffered (used on shutdown or urgent alert)."""
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
            # Wake on a short tick so a sparse batch still flushes ~0.5s after
            # its first event. The 0.05s granularity keeps urgent events instant.
            self._wake.wait(timeout=0.05)
            self._wake.clear()
            with self._lock:
                if not self._buffer:
                    continue
                has_urgent = any(e.get("urgent") for e in self._buffer)
                elapsed = time.time() - self._first_event_time
                if not has_urgent and len(self._buffer) < self._max_events and elapsed < self._flush_interval:
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

