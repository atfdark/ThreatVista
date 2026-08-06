# Sharing the ThreatVista Link & Getting Employee Sign-In / USB / Download Alerts

This guide answers three questions in plain detail:

1. **If I share `http://192.168.0.243:5173/`, what will the other person actually see?**
2. **How do I make it so an admin sees everything, and when an employee "signs in" the admin instantly sees their name + basic details?**
3. **How do I get notified when an employee plugs in / removes a pen drive or downloads something?**

It explains what **already works today**, what is **missing**, and gives copy‑paste code for the missing parts.

---

## Part 1 — What someone sees when they open your shared link

### The short answer

They will see **only your ThreatVista login page** — nothing else. They cannot see the dashboard, employee data, or anything on your machine.

### Why (the exact flow)

| Step | What happens | Where in code |
|------|--------------|---------------|
| 1 | Person opens `http://192.168.0.243:5173/` | Vite dev server serves the app |
| 2 | The app loads the route `/`, which renders `MainLayout` | `frontend/src/App.jsx` |
| 3 | `MainLayout` checks `localStorage.getItem('threatvista_token')` | `frontend/src/layouts/MainLayout.jsx` |
| 4 | No token exists in their browser → `navigate('/login')` | same file |
| 5 | They see the ThreatVista **login screen** | `frontend/src/pages/Login.jsx` |

### Why they can't sneak past the login page and see data

Even if they edit the frontend (DevTools), every data call goes to the backend and every data endpoint is protected:

- Every `/api` endpoint except login requires an `Authorization: Bearer <token>` header.
- The backend verifies the token is a real, un-expired JWT and that its session is **not revoked** (`backend/auth.py` → `get_current_user`).
- So without valid credentials they get `401 Unauthorized` — the frontend then kicks them back to `/login` (`frontend/src/services/mockData.js`).

**The login page is a door, and the door is locked at the server, not just the screen.**

### Three important caveats about sharing that link

1. **It only works on your Wi‑Fi / LAN.** `192.168.0.243` is a *private* network address. A friend on a different network (mobile data, another city) **cannot open it at all**. Sharing it only works for people connected to the same router. To share over the internet you would need port‑forwarding or a tunnel (ngrok/cloudflared) — not needed for a LAN demo.
2. **It's the development server.** `npm run dev` is meant for building, not serving real users. It's fine for a hackathon/LAN demo. If you ever want it on the internet, run `npm run build` and serve the `dist/` folder.
3. **The login page prints all the demo passwords to everyone** who opens it (`Login.jsx` shows `admin / admin123`, `analyst / analyst123`, `auditor / auditor123`). For anything beyond a demo, delete that info box — otherwise anyone who opens your link already has working credentials.

> ✅ **Checklist to be sure your shared link is safe**
> - [ ] Backend (`uvicorn`) and frontend (`npm run dev`) are both running.
> - [ ] Only people on your network can reach `192.168.0.243` (it's not forwarded/tunneled).
> - [ ] Remove the demo‑credentials box on the login page if real people should not have passwords.

---

## Part 2 — "Admin sees everything, employee sign‑ins show up to the admin"

### The current role model (what already exists)

The dashboard has **three roles today**, all of them *SOC staff*, not employees:

| Role | Username / Password | Access |
|------|---------------------|--------|
| **SOC Administrator** | `admin` / `admin123` | Everything: sessions, audit trail, settings, reports |
| **Security Analyst** | `analyst` / `analyst123` | Everything except the audit trail |
| **Read‑Only Auditor** | `auditor` / `auditor123` | View‑only, no writes |

Employees (Rahul Sharma, Amit Patel, Priya Singh, …) are **monitored subjects**, not dashboard users. They don't log into the web app — their **endpoint agent** (a Python program running on their laptop) reports activity to the backend.

### What already records "who signed in"

Even today, every dashboard login is tracked:

- `POST /api/auth/login` creates a **session row** (with IP, time, expiry) and writes an **audit‑log entry** `login` → `backend/api/routes.py`.
- `GET /api/auth/sessions` lists sessions; **admin can list any user's sessions** and can revoke/force‑logout any of them → `routes.py`.
- `GET /api/audit-logs` (admin only) is a full trail of logins, logouts, session revokes, settings changes.
- The **Active Sessions** page (`/sessions`) shows live endpoint **devices**: employee name, department, hostname, IP address, OS, online/offline, last heartbeat, CPU/RAM/disk, latest activity, and a live event stream → `frontend/src/pages/ActiveSessions.jsx`.

### What's missing for exactly what you described

| You asked | Exists today? | Gap |
|-----------|---------------|-----|
| Employees sign in | ❌ No employee login accounts | The dashboard has no `employee` role. Employees only exist as monitored endpoints. |
| Admin sees "someone signed in" with name + basic details | ⚠️ Partly | Sessions + audit log store it, but nothing shows it **live** to the admin, and login events are **not broadcast** over WebSocket. |
| Instant notification | ❌ | No toast/bell/email when a login or USB/download event happens. |

### Option A — Real employee login accounts (recommended if you want employees to actually sign in)

> ✅ **Now implemented.** The login page has **SOC / Admin** and **Employee** tabs; under Employee there's **Sign In** and **Create Account** (self-registration, stored in the `users` table with `role="employee"`). New accounts auto-log-in and land on a restricted `/me` profile page. SOC admins see every sign-in as a **live toast** (WebSocket `new_login`), plus `register`/`login` entries in the Audit page. Employees are **blocked (403)** from SOC-wide endpoints (`/dashboard`, `/employees`, `/alerts`, `/reports`, …) by the backend `soc_only` dependency.

1. **Add employee users** in `backend/database/db_setup.py` with `role="employee"` (same pattern used for `analyst`/`auditor`). Link the user to the `Employee` record so the admin sees a real name:

```python
# backend/database/db_setup.py (inside the seeding function)
for emp, pw in [("rahul.sharma@threatvista.com", "rahul123"),
                ("amit.verma@threatvista.com", "amit123"),
                ("priya.patel@threatvista.com", "priya123")]:
    if not db.query(User).filter(User.username == emp).first():
        db.add(User(username=emp, password_hash=hash_password(pw), role="employee"))
```

2. **Give employees their own landing page.** When the login response says `role === "employee"`, redirect them to a simple "my activity" page instead of the SOC dashboard. Gate it in `frontend/src/App.jsx` or `Sidebar.jsx` (which already hides `Settings` from auditors and `Audit` from non‑admins).

3. **Show live sign‑ins to the admin.** The backend already stores them. Now make them arrive in real time — see **Part 4** for the WebSocket broadcast, and add a small "Recent sign‑ins" card that consumes it.

### Option B — "Employee signed in" = "employee's endpoint is online" (simplest)

If you don't actually need employees to log into a web page (they just run the agent on their machine), then the **Active Sessions page already is** your admin view: it lists each employee's device, shows it ONLINE/OFFLINE live, and streams their activity. The "sign‑in" moment = their agent starts + heartbeat begins.

For this to work, each employee's laptop must run the agent with their email:
```bash
set AGENT_EMPLOYEE_EMAIL=rahul.sharma@threatvista.com
set BACKEND_URL=http://192.168.0.243:8000
python endpoint_agent/agent.py
```

---

## Part 3 — Pen‑drive (USB) insert/remove and download notifications

### What already monitors activity

- **File monitor** — watches `Desktop`, `Documents`, `Downloads`, and any mounted USB drive. Emits `file_create` / `file_delete` / `file_modify` / `file_move` with filename, extension, size, and folder → `endpoint_agent/monitors/file_monitor.py`.
- **Process monitor** — flags known risky processes → `endpoint_agent/monitors/process_monitor.py`.
- **USB monitor** — *intended* to report `usb_insert` / `usb_remove` → `endpoint_agent/monitors/usb_monitor.py`.

These events flow: **agent → `POST /api/events` → saved → risk scored → alert engine → WebSocket → dashboard (Active Sessions feed + Alerts page).**

### ✅ USB monitor — now event-driven (fixed)

The old monitor had two fatal flaws: it was **never actually triggered** (the WMI watcher was stored but never iterated, and `check_once()` was never scheduled), and a naive `check_once()` polling loop would re-report every already‑connected drive on every tick — spamming `usb_insert`.

[`endpoint_agent/monitors/usb_monitor.py`](../endpoint_agent/monitors/usb_monitor.py) now spins up **two background daemon threads** from `start()`:

| Thread | WMI event | Fires when |
|--------|-----------|------------|
| `usb-insert-watcher` | `Win32_LogicalDisk` **creation** | a USB drive is plugged in and Windows mounts it |
| `usb-remove-watcher` | `Win32_LogicalDisk` **deletion** | a USB drive is ejected / pulled out |

- **Event-driven, not polling** — WMI blocks until the OS fires the event; zero CPU waste while idle.
- **1-second timeout loop** — `stop()` exits cleanly within ~1 second.
- **`CoInitialize`/`CoUninitialize` per thread** — correct COM threading model on Windows.
- **Graceful fallback** — if pywin32/WMI isn't installed it prints a warning and returns `False`, so the agent keeps running without USB monitoring.
- Emits `usb_insert` **and `usb_remove`** — the correlation engine already supports `usb_remove` in its evidence‑destruction rule ([ai/correlation.py](../ai/correlation.py)), the USB report includes it, and demo scenarios replay it.
- Filters to `DriveType == 2` (removable media) so CD/network/local‑disk activity doesn't spam the feed.
- **No `agent.py` changes needed** — the `start()` / `stop()` interface is identical.

### "Download something"

Today a download is detected indirectly: any file that appears in the **Downloads** folder becomes a `file_create` event with `folder` = `Downloads`. That's already enough to show *"file_create: photo.zip in Downloads"* in the live feed and Alerts. There is **no browser‑download hook** (that would require a browser extension or OS network inspection) — folder watching is the practical approach here.

### How the notification reaches YOU

Today notifications only appear **inside the dashboard** (live feed + Alerts page). If you want to be told without staring at the screen, pick a channel:

#### Channel 1 — Live toast + native browser notification (fastest to build)

1. **Broadcast login events over WebSocket** (login is currently not broadcast). In `backend/api/routes.py` make `login` an `async def` and add after the audit log line:

```python
await manager.broadcast({
    "type": "new_login",
    "data": {
        "username": user.username,
        "role": user.role,
        "ip": ip,
        "at": datetime.utcnow().isoformat(),
    },
})
```

2. **Listen for it in the frontend** and pop a toast + native notification. Add a `useWebSocket` handler in `MainLayout.jsx`:

```jsx
useWebSocket((msg) => {
  if (msg.type === "new_login") {
    // toast
    console.log(`👤 ${msg.data.username} signed in from ${msg.data.ip}`);
    // native desktop notification
    if ("Notification" in window && Notification.permission === "granted") {
      new Notification("ThreatVista — Employee Sign-In", {
        body: `${msg.data.username} (${msg.data.role}) logged in from ${msg.data.ip}`,
      });
    }
  }
});
```

3. Ask for permission once, on login page mount: `Notification.requestPermission()`.

USB events and file/download events already come over the same socket (`type: "new_event"`), so the same handler can fire a notification for `usb_insert` / `usb_remove` / `file_create` with `folder === "Downloads"`.

#### Channel 2 — Email alert on high/critical alerts

In `backend/services/alert_engine.py` (or the events route, after `alerts` are created), send email via SMTP when an alert severity is High/Critical:

```python
import smtplib
from email.mime.text import MIMEText

def send_alert_email(alert):
    msg = MIMEText(f"ThreatVista alert [{alert.severity}]: {alert.reason}")
    msg["Subject"] = f"ThreatVista: {alert.severity} alert"
    msg["From"] = "threatvista@yourdomain.com"
    msg["To"] = "you@yourdomain.com"
    with smtplib.SMTP("smtp.gmail.com", 587) as s:
        s.starttls()
        s.login("threatvista@yourdomain.com", "app_password")
        s.send_message(msg)
```

#### Channel 3 — Telegram/WhatsApp push (best for instant "ping me" alerts)

Use a bot token + chat id:

```python
import requests
requests.post(
    f"https://api.telegram.org/bot<TOKEN>/sendMessage",
    json={"chat_id": "<CHAT_ID>", "text": f"⚠️ {alert.severity}: {alert.reason}"},
)
```

---

## Part 4 — Step‑by‑step plan (in priority order)

**To lock down and understand your shared link (Part 1)**
- [ ] Keep it LAN‑only for now (no port forwarding/tunnel).
- [ ] Remove the demo‑credentials box from `Login.jsx` if real people will use it.

**To see employee sign‑ins as admin (Part 2)**
- [ ] Pick **Option A** (employee accounts) or **Option B** (endpoint‑online = signed in). Option B needs zero new code.
- [ ] Broadcast login events over WebSocket (code above) so sign‑ins arrive live.
- [ ] Add a "Recent sign‑ins" card to the Dashboard that listens for `new_login`.

**To get USB + download notifications (Part 3)**
- [ ] Apply the USB monitor fix (code above) — this is the missing piece for pen‑drive insert/remove.
- [ ] Watch for `usb_insert`, `usb_remove`, and `file_create` with `folder` containing `Downloads`.
- [ ] Add toast + native notification in `MainLayout.jsx` (Channel 1), or email/Telegram (Channels 2/3).

**Verification**
- [ ] Run agent with a USB stick plugged in → unplug it → confirm `usb_insert` / `usb_remove` appear in the Active Sessions live feed within ~3 seconds.
- [ ] Log in as a second user in another browser → confirm the admin's screen shows the `new_login` toast instantly.
