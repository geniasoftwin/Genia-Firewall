@echo off
setlocal
cd /d "%~dp0"

fltmc >nul 2>&1
if errorlevel 1 (
  echo ERROR: run this script as Administrator.
  pause
  exit /b 1
)

if not exist ".\GeniaFirewall.Service.exe" (
  echo ERROR: GeniaFirewall.Service.exe not found.
  pause
  exit /b 1
)

echo Starting GeniaFirewall.Service in console test mode.
echo If the installed service is already running, stop it first.
echo Press Ctrl+C to exit.
echo.
".\GeniaFirewall.Service.exe" --console
pause
