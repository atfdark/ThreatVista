@echo off
REM ============================================================
REM  ThreatVista Endpoint Agent - one-click launcher
REM  Run this on an EMPLOYEE laptop (Windows, Python 3.10+ installed).
REM
REM  Usage:
REM    start_agent.bat                       (uses saved config / interactive prompt if IP changed)
REM    start_agent.bat 10.157.56.246:8000    (connect to specific IP/port on same Wi-Fi)
REM    start_agent.bat https://xyz.ngrok-free.app (connect across different internet/tunnel)
REM ============================================================
setlocal

REM Run from the folder containing this file
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
echo   ========================================
echo.

echo   [1/2] Checking agent dependencies...
python -m pip install --quiet requests watchdog psutil pywin32 cryptography
if errorlevel 1 (
    echo.
    echo   [!] Dependency install failed. Check your internet connection.
    echo.
    pause
    exit /b 1
)

echo   [2/2] Starting monitoring. Press Ctrl+C to stop.
echo.

if exist "endpoint_agent\agent.py" (
    python -m endpoint_agent.agent %*
) else (
    python agent.py %*
)

echo.
echo   Agent stopped.
pause
