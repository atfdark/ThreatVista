@echo off
REM ============================================================
REM  ThreatVista Endpoint Agent - one-click launcher
REM  Run this on an EMPLOYEE laptop (Windows, Python 3.10+ installed).
REM
REM  No arguments needed. Before running:
REM    1. Log in to ThreatVista on this laptop.
REM    2. Open your profile and click "Connect This Device".
REM    3. The browser downloads threatvista-agent-config.json.
REM       Leave it next to this file (or in Downloads).
REM    4. Double-click this file. Done.
REM
REM  What it does:
REM    1. Installs the agent's Python dependencies (safe to re-run).
REM    2. Registers this laptop as the employee's device (shows in
REM       Active Sessions as ONLINE) and consumes the enrollment token.
REM    3. Streams USB / file / process / network activity to the SOC
REM       dashboard in real time.
REM ============================================================
setlocal

REM Run from the folder containing this file (the project root)
cd /d "%~dp0"

REM Make sure Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo   [!] Python not found. Install Python 3.10+ and tick "Add Python to PATH",
    echo       then run this file again.
    echo.
    pause
    exit /b 1
)

echo.
echo   ========================================
echo    ThreatVista Endpoint Agent
echo    Backend  : read from threatvista-agent-config.json
echo   ========================================
echo.

echo   [1/2] Installing agent dependencies...
python -m pip install --quiet --upgrade pip
python -m pip install --quiet requests watchdog psutil pywin32 wmi
if errorlevel 1 (
    echo.
    echo   [!] Dependency install failed. Check your internet connection.
    echo.
    pause
    exit /b 1
)

echo   [2/2] Starting monitoring. Press Ctrl+C to stop.
echo.

python -m endpoint_agent.agent

echo.
echo   Agent stopped.
pause
