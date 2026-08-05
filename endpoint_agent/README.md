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

On startup the agent:

1. Reads **`AGENT_EMPLOYEE_EMAIL`** (which employee this machine belongs to).
2. Collects a **device profile** — hostname, OS version/build, CPU model/cores,
   RAM, disk, local IP, agent version (`get_device_info()`).
3. Calls **`POST /api/agent/register`** — the backend resolves the employee by
   email and creates/updates their `Device` profile, returning a `device_id`.
4. Starts a **heartbeat loop** — sends `POST /api/agent/heartbeat` every
   `AGENT_HEARTBEAT_SECONDS` (default 30s) so the dashboard marks the endpoint
   **online**. Without a heartbeat for ~90s the endpoint shows **offline**.
5. Every monitored action is sent as an event with the resolved `employee_id`.

## Configuration (environment variables)

| Variable | Purpose | Default |
|----------|---------|---------|
| `AGENT_EMPLOYEE_EMAIL` | Employee this machine belongs to | `rahul.sharma@threatvista.com` |
| `AGENT_HEARTBEAT_SECONDS` | Heartbeat interval | `30` |
| `THREATVISTA_AGENT_KEY` | Shared secret (if the backend requires `X-Agent-Key`) | *(empty)* |

## Running

```bash
# From the project root, with the backend already running:
python endpoint_agent/agent.py
```

## Monitors

| Monitor | Library | Emits |
|---------|---------|-------|
| `file_monitor.py` | watchdog | file created / moved / renamed / deleted |
| `usb_monitor.py` | WMI / pywin32 (Windows) | USB insert / remove |
| `process_monitor.py` | psutil | process start / stop |
| `system_monitor.py` | psutil | system_metrics (CPU/RAM/disk) + device profile + heartbeats |

## Known limitations

- **No offline queue** — events POST directly; if the backend is unreachable the
  event is dropped (logged). A local SQLite buffer is future work.
- **Network-upload monitor** — `get_network_connections()` helper exists but is
  not yet wired into the event stream.
- **Single employee per agent** — each agent belongs to one employee (the email
  in config).
