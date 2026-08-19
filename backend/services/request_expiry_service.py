"""
ThreatVista Automatic Approval Request Expiration Daemon.

Runs in the background every 30-60 seconds:
- Identifies PENDING ActionRequest tickets that have exceeded the 5-minute TTL.
- Transitions their status to EXPIRED.
- Maintains active file protection on endpoint.
- Broadcasts real-time WebSocket events (`REQUEST_EXPIRED`) to update SOC dashboard badges.
"""
import time
import threading
from datetime import datetime
from typing import List
from sqlalchemy.orm import Session

from backend.database.connection import SessionLocal
from backend.models.database import ActionRequest
from backend.websocket.manager import manager


def expire_stale_requests(db: Session) -> List[int]:
    """Scan and expire pending action requests older than 5 minutes."""
    from backend.services.action_request_service import action_request_to_dict, get_pending_count

    now = datetime.utcnow()
    stale_requests = (
        db.query(ActionRequest)
        .filter(
            ActionRequest.status == "PENDING",
            ActionRequest.expires_at != None,
            ActionRequest.expires_at <= now,
        )
        .all()
    )

    if not stale_requests:
        return []

    expired_ids = []
    for req in stale_requests:
        req.status = "EXPIRED"
        req.resolved_at = now
        req.resolved_by = "System Auto-Expiry"
        req.resolution_notes = "Action request automatically expired after 5-minute TTL (file protection maintained)"
        expired_ids.append(req.id)

    db.commit()

    pending_count = get_pending_count(db)

    # Broadcast expiration event for each expired ticket
    for req in stale_requests:
        data = action_request_to_dict(req)
        manager.broadcast_nowait({
            "type": "REQUEST_EXPIRED",
            "request_id": req.id,
            "action_request": data,
            "pending_count": pending_count,
        })
        print(f"[⏱️ ThreatVista Expiry] Action request #{req.id} auto-expired (5m TTL exceeded).")

    return expired_ids


_expiry_daemon_started = False
_daemon_lock = threading.Lock()


def start_expiry_daemon(interval_seconds: int = 30):
    """Start background scheduler loop once."""
    global _expiry_daemon_started
    with _daemon_lock:
        if _expiry_daemon_started:
            return
        _expiry_daemon_started = True

    def _loop():
        while True:
            try:
                db = SessionLocal()
                try:
                    expire_stale_requests(db)
                finally:
                    db.close()
            except Exception as e:
                print(f"[-] Expiry daemon error: {e}")
            time.sleep(interval_seconds)

    thread = threading.Thread(target=_loop, daemon=True, name="ThreatVista-ExpiryDaemon")
    thread.start()
    print(f"[+] Automatic Request Expiration daemon started (interval: {interval_seconds}s).")
