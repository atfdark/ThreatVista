@echo off
REM ============================================================
REM  ThreatVista Backend Server Launcher (LAN / Multi-Device Ready)
REM  Binds to 0.0.0.0 so endpoint agents on other laptops can connect.
REM ============================================================
setlocal
cd /d "%~dp0"

echo.
echo   ========================================
echo    ThreatVista Backend Server
echo   ========================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python not found in PATH.
    pause
    exit /b 1
)

echo [*] Starting ThreatVista API server on 0.0.0.0:8000...
echo [*] Endpoint agents on your Wi-Fi can connect via your LAN IP.
echo.

python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
pause
