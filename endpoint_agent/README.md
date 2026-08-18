# Endpoint Monitoring Agent

The ThreatVista **endpoint agent** runs silently in the background of an
employee's machine (the "sensor"). It collects **metadata only** — never file
contents — and streams it to the FastAPI backend. The React dashboard only
*visualizes* the data the backend receives.

## Architecture

```
Employee PC ──► Agent (this directory) ──► FastAPI Backend ──► SOC Dashboard
   │              │                           │
   │              ├─ device registration      ├─ maps agent → employee
   │              ├─ heartbeats               ├─ online/offline status
   │              └─ telemetry events         └─ AI risk analysis
   └─ file / USB / process / system events
```

## How identity works

There is **no manual email** anymore. An employee enrolls this laptop through
the ThreatVista web portal, then runs the agent — it wires itself up.

1. The employee logs in to ThreatVista, opens their profile and clicks
   **Connect This Device**. The page calls `POST /api/agent/enroll`, which
   issues a **one-time enrollment token** (random UUID, expires in 10 minutes)
   and downloads `threatvista-agent-config.json` (`{"token", "backend_url"}`).
2. The employee double-clicks **`start_agent.bat`** (no arguments). The agent
   reads the config file, collects a **device profile** (hostname, OS, CPU, RAM,
   disk, local IP, agent version) and calls **`POST /api/agent/register`** with
   `enrollment_token`.
3. The backend validates the token (not expired / not used), resolves the
   employee, registers/updates their `Device`, **consumes the token** and
   broadcasts `device_connected` over WebSocket so the dashboard updates
   instantly. The agent deletes the config file after success.
4. The agent saves its resolved identity (`threatvista-agent-device.json`), so
   the **next run reconnects to the same device** — no duplicate registration,
   no re-enrollment.
5. A **heartbeat loop** sends `POST /api/agent/heartbeat` every
   `AGENT_HEARTBEAT_SECONDS` (default 30s) so the dashboard marks the endpoint
   **online**. Without a heartbeat for ~180s the endpoint shows **offline**.
6. Every monitored action is sent as an event with the resolved `employee_id`.

## Configuration (environment variables)

| Variable | Purpose | Default |
|----------|---------|---------|
| `AGENT_HEARTBEAT_SECONDS` | Heartbeat interval | `30` |
| `THREATVISTA_AGENT_KEY` | Shared secret (if the backend requires `X-Agent-Key`) | *(empty)* |

The backend URL and enrollment token come from
`threatvista-agent-config.json`, not environment variables.

## Running & Dynamic IP / Network Changes

The agent supports automatic network reconnection across changing Wi-Fi networks and remote internet connections:

### 1. Default Run (Same Wi-Fi / Local Network)
```bash
# Double-click or run from terminal:
.\start_agent.bat
```
- If the server's IP changed (e.g. from `192.168.0.x` to `10.157.56.x`), the agent will automatically prompt:
  ```text
  [!] Could not reach ThreatVista backend at: http://...
  [?] Enter new Backend IP/URL:
  ```
  Type the server's current IP (e.g., `http://10.157.56.246:8000`), and the agent will verify the connection and update `threatvista-agent-device.json` automatically!

### 2. Passing the Backend IP Directly
```bash
# Pass the IP as a command-line argument:
.\start_agent.bat 10.157.56.246:8000
# Or via Python:
python -m endpoint_agent.agent --backend-url http://10.157.56.246:8000
```

### 3. Remote / Different Internet Connections (Across Networks / 4G / WAN)
If the backend and employee laptop are on **different internet connections** (e.g. employee is remote, or on mobile data), private LAN IPs (`192.168.x.x` / `10.x.x.x`) cannot be reached directly.

1. **On the Backend PC**, start a free tunnel:
   ```bash
   ngrok http 8000
   # Or: cloudflared tunnel --url http://localhost:8000
   ```
2. **On the Employee Laptop**, connect using the public tunnel URL:
   ```bash
   .\start_agent.bat https://your-tunnel-subdomain.ngrok-free.app
   ```
   The agent will stream telemetry securely across the internet to the backend!

## Monitors

| Monitor | Library | Emits |
|---------|---------|-------|
| `file_monitor.py` | watchdog | file + **folder** created / moved / deleted; watches the **OneDrive-redirected** Desktop / Documents / Downloads (so files on a redirected desktop are seen) |
| `usb_monitor.py` | ctypes (Windows API polling) | USB insert / remove |
| `process_monitor.py` | psutil | process start / stop |
| `system_monitor.py` | psutil | system_metrics (CPU/RAM/disk) + device profile + heartbeats |
| `network_monitor.py` | psutil | network upload **spikes** (rolling baseline; routine cloud sync does NOT alarm) |

## Known limitations

- **No offline queue** — events POST directly; if the backend is unreachable the
  agent exits and asks you to start the backend. A local SQLite buffer is future
  work.
- **Enrollment requires the web portal** — if the config file is missing or its
  token expired, the agent falls back to the saved device identity (no
  re-enrollment) when one exists; otherwise it prints instructions and exits.
- **Network-upload monitor** — machine-wide counters can't attribute traffic to
  a process; the monitor uses a rolling baseline so routine cloud sync is not
  flagged, but genuinely large sustained exfiltration is.
- **Single employee per agent** — each agent belongs to the employee who
  enrolled it.
