# ThreatVista — Hackathon Presentation & Live Demo Guide

A 5–7 minute walkthrough script for presenting ThreatVista to judges.

---

## 🎯 The Pitch (1 min)

> "Traditional DLP systems read file contents — invading employee privacy while missing the smarter insider. **ThreatVista flips the model: it monitors only metadata.** What files, how many, when, to which USB — never *what's inside* them. An Isolation Forest model learns each employee's normal 'Behavior DNA' and flags when reality deviates, so exfiltration is caught before damage, with full explainability."

**Key selling points to land:**
- Privacy-first: metadata only, zero content inspection.
- Behavior DNA: per-employee baselines, not global rules.
- Explainable: every risk score says *why*.
- Real-time: WebSocket push to a SOC-grade dashboard.

---

## 🏗 Architecture Walkthrough (1 min)

Show the diagram in `docs/architecture.md`:

```
Employee Activity → Endpoint Agent → SQLite → Feature Engineering
→ Behavior DNA → Isolation Forest → Correlation → Risk Score → XAI
→ FastAPI → WebSocket → React SOC Dashboard → Administrator
```

---

## 🖥 Live Demo (3–4 min)

### 0. Start everything
```bash
# Terminal 1 — backend
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

# Terminal 2 — frontend
cd frontend && npm run dev

# Browser → http://localhost:5173
```

### 1. Login (30 sec)
- Log in as **admin / admin123** (or **analyst / analyst123**).
- Point out the role chip in the sidebar ("SOC Administrator").
- Emphasize: bcrypt-hashed passwords, signed JWTs, protected routes — the dashboard rejects unauthenticated API calls with `401`.

### 2. Initial dashboard (30 sec)
- Three employees already profiled: **Rahul (Critical)**, **Amit (Medium)**, **Priya (Safe)** — the AI pipeline has scored them from real event history.
- Show the stat cards, risk distribution, and live metadata feed.

### 3. Trigger the insider-threat attack (90 sec)
```bash
python scripts/demo_scenarios.py
```
Watch the dashboard update live as events stream in:

| Scenario | What happens | Dashboard outcome |
|----------|--------------|-------------------|
| 1. Normal | Priya edits docs | Stays **Safe (0)** — no false alarm |
| 2. USB | Amit inserts USB, copies 5 files | Escalates to **Medium (60)** |
| 3. Insider | Rahul logs in midnight, USB, mass-copy, upload | **Critical (100)** — alert fires |
| 4. Cover-up | Amit deletes evidence, wipes | **Critical (100)** |

### 4. Show explainability (30 sec)
- Open Rahul's profile → **AI Recommendations** panel.
- Read the reasons aloud: *"USB device inserted", "Mass file operations (>100 in 24h)", "Large network upload spike", "USB + mass copy = possible mass data exfiltration"*.
- Show the recommendations (block USB, restrict bandwidth, forensic log collection).

### 5. Settings prove the engine is configurable (20 sec)
- Go to **Settings**, drag the "High Risk Classification Threshold", save.
- Re-run an analysis — classification responds to the persisted config.

### 6. Show the enterprise EDR layer (60 sec)
The dashboard isn't just a website — real **agents** run on each machine. Show:

- **Online Endpoints** stat card on the dashboard (`3/3 online`).
- Open **Rahul's profile** → his machine is **ONLINE** (green pulse, "last heartbeat Xs ago").
- **Endpoint Device Profile**: hostname `RHLAPTOP01`, Windows 11, Intel i7, 32 GB RAM, IP.
- **Endpoint Health**: live CPU / RAM / disk usage bars from the agent's heartbeat.
- **Behavior Timeline**: login at 12:30 AM → USB insert → 150+ file copies → upload, with the risk reasons attached.
- **Activity Explorer**: tab through USB history / processes / files.
- **AI Confidence**: 99% on Rahul's Critical assessment.
- **Remote Commands**: click *Disable USB* → confirmation "dispatched (simulated)" + command history row.

To show online→offline live: stop the agent (or wait 90s without a heartbeat) and the badge flips to **OFFLINE**.

---

## 💡 Judge Q&A Prep

**"Doesn't this invade privacy?"**
> No — ThreatVista stores metadata (timestamps, file sizes, counts, USB IDs, upload volumes). It never opens, reads, or inspects document contents. Privacy-first by design.

**"How is Behavior DNA different from rules?"**
> Rules say "USB is bad." DNA says "USB *outside this employee's normal pattern* is bad." Priya's USB use is normal; Rahul's midnight 700-file copy is not. The Isolation Forest learns this per-employee.

**"Why metadata if content is the real signal?"**
> Content DLP is heavy, privacy-hostile, and bypassable. Metadata captures *behavior* — the intent signal — at near-zero cost, and it's impossible to hide the act of copying 700 files.

**"Can it be fooled?"**
> Like any detection, sophisticated attackers adapt — which is why ThreatVista also correlates *cover-up* behavior (evidence deletion, USB removal, disk-wiping), and why future work adds periodic model retraining.

---

## 🚀 Future Enhancements (for the closing slide)

- Offline-queue the endpoint agent (local SQLite buffer + sync).
- Auto-retrain Isolation Forest as behavior evolves.
- Notifications (email / Slack) on Critical alerts.
- Policy enforcement hooks (USB block, bandwidth throttle).
