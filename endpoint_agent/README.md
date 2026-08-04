# Endpoint Monitoring Agent

This directory will contain the Windows client agent which collects OS metadata.

## Technology Stack
* **Watchdog**: Directory & file operations hook (creation, deletion, modification, rename).
* **psutil**: System processes, CPU, memory, and active TCP connections.
* **pywin32 / WMI**: Windows Management Instrumentation APIs to monitor hardware events (e.g., USB drive insertion).

## Planned Architecture
The agent runs locally as a Windows Service, logging raw events directly to the local SQLite database. In Phase 2, we will implement the event listener loops and write them to the DB.
