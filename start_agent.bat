@echo off
REM ============================================================
REM  ThreatVista Endpoint Agent - one-click launcher
REM  Run this on an EMPLOYEE laptop (Windows, Python 3.10+ installed).
REM
REM  Usage:   start_agent.bat <employee-email>
REM  Example: start_agent.bat kamaal@gmail.com
REM
REM  What it does:
REM    1. Installs the agent's Python dependencies (safe to re-run).
REM    2. Registers this laptop as the employee's device (shows in
REM       Active Sessions as ONLINE).
REM    3. Streams USB / file / process / network activity to the SOC
REM       dashboard in real time.
REM ============================================================
setlocal

REM ---- EDIT THIS: your SOC server's LAN IP (the admin laptop) ----
set "BACKEND_URL=http://192.168.0.243:8000"
REM ----------------------------------------------------------------

set "AGENT_EMPLOYEE_EMAIL=%~1"
if "%AGENT_EMPLOYEE_EMAIL%"=="" (
    echo.
    echo   Usage: start_agent.bat ^<employee-email^>
    echo   Example: start_agent.bat kamaal@gmail.com
    echo.
    exit /b 1
)

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
echo    Employee : %AGENT_EMPLOYEE_EMAIL%
echo    Backend  : %BACKEND_URL%
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
