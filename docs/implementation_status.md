# ThreatVista — Implementation Status

*Last verified: 2026-08-05*

This document records how much of the ThreatVista project is implemented, module
by module and feature by feature, against the original phase plan. It is written
so a judge (or a new contributor) can see exactly what works, what is verified,
and what remains as known gaps.

**Overall completion: ~95% — fully demo-ready.** The complete detection pipeline
and enterprise EDR architecture (agent registration, heartbeats, online status,
device profiles, behavior timelines, AI confidence, simulated remote commands)
run end-to-end; the remaining ~5% is production hardening, not core features.

---

## 🧩 Module-by-Module Status

| Module | Path | Status | Notes |
|--------|------|--------|-------|
| AI Engine | `ai/` | ✅ **Complete** | 10 modules: preprocessing, features, DNA, Isolation Forest, correlation, risk, XAI, training |
| Backend API | `backend/` | ✅ **Complete** | FastAPI, 19+ endpoints, auth, sessions, audit, reports, settings |
| Frontend | `frontend/` | ✅ **Complete** | React 19 + Vite, 8 pages, role-based navigation |
| Endpoint Agent | `endpoint_agent/` | 🟡 **Mostly complete** | File/USB/process/system monitors work; network-upload + offline queue gaps |
| Database | `database/` | ✅ **Complete** | 9 tables, seeded + migrated |
| ML Model | `models/` | ✅ **Shipped** | Trained `isolation_forest.joblib` |
| Docs | `docs/` | ✅ **Complete** | architecture, workflow, demo guide, implementation status |
| Demo Tooling | `scripts/` | ✅ **Complete** | `demo_scenarios.py`, `reset_db.py` |

---

## ✨ Feature-by-Feature Status

### 1. Telemetry & Endpoint Monitoring

| Feature | Status | Detail |
|---------|--------|--------|
| File monitoring (create/copy/delete/modify/rename) | ✅ | Watchdog (`file_monitor.py`) |
| USB insertion detection | ✅ | WMI/PnP (`usb_monitor.py`) |
| Process monitoring | ✅ | psutil (`process_monitor.py`) |
| System metrics (CPU/RAM) | ✅ | 60s loop |
| Network upload telemetry | 🟡 | Helper exists (`get_network_connections`) but **not wired** into the event stream |
| Offline event queue / sync | ❌ | Agent POSTs directly; no local buffer (logged as "not implemented") |
| Agent identity | ✅ | Device **auto-registration** keyed to `AGENT_EMPLOYEE_EMAIL` → backend maps to employee |
| Device heartbeat (online/offline) | ✅ | Agent sends heartbeats every `AGENT_HEARTBEAT_SECONDS`; device goes offline after ~90s without one |
| Device profile collection | ✅ | `get_device_info()` — hostname, OS/version, CPU, cores, RAM, disk, IP, agent version |

### 2. AI Threat Engine

| Feature | Status | Detail |
|---------|--------|--------|
| Event preprocessing | ✅ | `preprocessing.py` |
| Feature engineering (16 features, 24h/1h windows) | ✅ | `features.py`; IST-aware night/weekend detection; parses mass-copy counts from `details` |
| Behavior DNA baselines | ✅ | `dna.py` — working hours, USB/copy/upload averages |
| Isolation Forest anomaly detection | ✅ | `model.py`, trained model ships in `models/` |
| Event correlation | ✅ | `correlation.py` — USB mass-exfil, night upload, evidence destruction, process+file, rapid ops, USB staging |
| Risk scoring (0–100) | ✅ | `risk.py` — configurable Safe/Medium/High/Critical thresholds |
| Explainable AI | ✅ | `xai.py` — human-readable reasons + recommendations |
| AI confidence score | ✅ | `xai._confidence()` — 0–100 from evidence strength (reasons, deviations, anomaly flag); shown on the profile |
| Model training | ✅ | `train.py` (optional; model ships trained) |
| Automated retraining loop | ❌ | Not scheduled; manual via `train.py` |

### 3. Backend API & Services

| Feature | Status | Detail |
|---------|--------|--------|
| Health / status | ✅ | `GET /api/status` |
| Dashboard aggregate + AI re-scoring | ✅ | `GET /api/dashboard` |
| Employee list / detail | ✅ | `GET /api/employees[/{id}]` with live AI analysis |
| Event ingest / query | ✅ | `POST/GET /api/events`, `GET /api/events/recent` |
| Alert ledger | ✅ | `GET /api/alerts` |
| **Alert lifecycle persistence** | ✅ | `PATCH /api/alerts/{id}` — Active → Investigating → Resolved, audit-logged + WebSocket broadcast |
| Real-time WebSocket | ✅ | `/ws` broadcasts `new_event`, `new_alert`, `alert_updated` |
| Settings persistence | ✅ | `GET/PUT /api/settings` → `system_config` table; drives risk thresholds |
| Reports (7 types) | ✅ | `GET /api/reports/{type}` — daily/weekly/monthly/high-risk/USB/file/network; JSON/CSV/HTML |
| Audit trail | ✅ | `GET /api/audit-logs` (admin) — logs login, alert updates, settings, reports |
| Session management | ✅ | `GET/DELETE /api/auth/sessions` — server-side revocation |
| Agent auth (shared secret) | ✅ | Optional `X-Agent-Key` via `THREATVISTA_AGENT_KEY` |
| Agent device registration | ✅ | `POST /api/agent/register` — resolves employee by email, upserts Device |
| Agent heartbeat | ✅ | `POST /api/agent/heartbeat` — refreshes `last_seen`, CPU/RAM/disk health |
| Online / offline status | ✅ | Device `last_seen` within 90s → online; exposed on employee list, detail, dashboard |
| Endpoint device + health | ✅ | `GET /api/employees/{id}` returns `device`, `endpoint_health`, `online`, `commands` |
| Remote commands (simulated) | ✅ | `POST/GET /api/employees/{id}/commands` — disable_usb, restart_agent, collect_logs, refresh_config |

### 4. Authentication & Roles

| Feature | Status | Detail |
|---------|--------|--------|
| Password hashing | ✅ | bcrypt |
| JWT issuance/verification | ✅ | python-jose HS256; `jti` embedded for session revocation |
| Login throttling / lockout | ✅ | 5 fails → 15-min lockout (`429`) |
| Real logout (session revocation) | ✅ | Server-side revoke |
| Role-based access | ✅ | **admin** (full + audit), **analyst** (ops), **auditor** (read-only) |
| Protected routes | ✅ | Unauthenticated requests → `401` |

### 5. Frontend SOC Dashboard

| Page | Status | Detail |
|------|--------|--------|
| Login | ✅ | Real JWT; shows both demo accounts |
| Dashboard | ✅ | Stat cards, live event feed, ranked employees, high-risk alerts, WebSocket live |
| Employees / DNA profile | ✅ | Directory + detail (Behavior DNA, risk trend, AI recommendations, raw telemetry) |
| Alerts | ✅ | Ledger with severity/status filters, employee links |
| Analytics | ✅ | Risk/severity distributions, weekly telemetry trends |
| Settings | ✅ | Loads + persists real config; affects AI engine |
| Reports | ✅ | 7 report types, downloadable |
| Audit | ✅ | Admin-only trail viewer |
| Role-based nav | ✅ | Auditor hides Settings; only admin sees Audit |

### 6. Database Schema

| Table | Purpose |
|-------|---------|
| `users` | Admin / analyst / auditor accounts (bcrypt hashes, roles) |
| `sessions` | JWT session records (revocation) |
| `employees` | 3 seeded employees |
| `events` | Telemetry |
| `alerts` | Correlation alerts |
| `risk_scores` | Historical score timeline (21 rows) |
| `behavior_profiles` | Per-employee DNA baseline (3 rows) |
| `system_config` | Persisted engine settings (1 row) |
| `audit_logs` | Security audit trail |
| `devices` | Endpoint device profiles (3 seeded, online) |
| `remote_commands` | Simulated command history |

---

## ✅ Verified End-to-End (this session)

- [x] Auth flow: login (admin/analyst/auditor), role check, `401` on missing token
- [x] Protected dashboard + AI analysis + settings + reports + audit endpoints
- [x] Event ingest → alert generation → **WebSocket broadcast** in real time
- [x] Settings thresholds genuinely change AI classification (score 55 flips Medium↔Safe↔High)
- [x] Agent register + heartbeat → online status flips; device info + health surfaced
- [x] Remote command dispatch (admin/analyst); auditor correctly denied (`403`)
- [x] AI confidence surfaced on every analysis (Rahul 99 / Amit 82 / Priya 50)
- [x] All 4 demo scenarios produce expected outcomes:

| Scenario | Expected | Result |
|----------|----------|--------|
| 1. Normal employee | Safe | ✅ Safe (0) |
| 2. USB + 5 files | Medium | ✅ Medium (60) |
| 3. Insider threat | Critical | ✅ Critical (100) |
| 4. Cover-up attempt | Critical | ✅ Critical (100) |

---

## 🟡 Known Gaps / Not Implemented

1. **Endpoint agent offline queueing** — no local SQLite buffer; events POST directly and are lost if the backend is down.
2. **Endpoint agent network-upload monitor** — helper exists (`get_network_connections`) but not wired into the event stream.
3. **Automated model retraining** — Isolation Forest is trained once; no scheduled retrain loop.
4. **`system_metrics` events** — carry weight 0 in the RiskEngine (harmless noise).
5. **Frontend mock fallbacks** — remain as offline resilience; real data is used whenever the backend is reachable.
6. **Real DLP enforcement** — USB blocking / bandwidth throttling are described (recommendations) but not actually enforced.
7. **Real remote-command execution** — commands are recorded/simulated; nothing is sent to the endpoint machine (by design for the hackathon).
8. **Interactive agent login GUI** — agent auto-registers from `AGENT_EMPLOYEE_EMAIL`; no on-screen login prompt.

---

## 📋 Phase Alignment

| Phase | Deliverable | Status |
|-------|-------------|--------|
| 1 | Architecture, backend skeleton, frontend scaffold, docs | ✅ |
| 2 | Endpoint monitoring, database schema, alert engine | ✅ |
| 3 | AI engine (DNA, Isolation Forest, correlation, risk, XAI) | ✅ |
| 4 | Integration, real-time dashboard, auth, testing, demo, docs | ✅ (~90%) |

---

## 🔧 How to Re-verify

```bash
# 1. Backend (port 8000)
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

# 2. Frontend (port 5173)
cd frontend && npm run dev

# 3. Browser → http://localhost:5173, login admin/admin123

# 4. Replay the 4 judge scenarios (watch the live feed)
python scripts/demo_scenarios.py

# 5. Reset the DB to a clean seeded state (backup created automatically)
python scripts/reset_db.py
```

See [docs/demo_guide.md](demo_guide.md) for the full presentation script.
