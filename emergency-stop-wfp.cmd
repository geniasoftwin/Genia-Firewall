@echo off
setlocal
set "SERVICE_NAME=GeniaFirewallService"
set "POLICY=%ProgramData%\GeniaFirewall\Service\wfp-policy.json"
set "BACKUP=%ProgramData%\GeniaFirewall\Service\wfp-policy.emergency-backup.json"

fltmc >nul 2>&1
if errorlevel 1 (
  echo ERROR: run this script as Administrator.
  pause
  exit /b 1
)

echo Emergency disabling GeniaFirewall WFP backend...
sc.exe stop "%SERVICE_NAME%" >nul 2>&1
if exist "%POLICY%" (
  if exist "%BACKUP%" del /q "%BACKUP%"
  move /Y "%POLICY%" "%BACKUP%" >nul
  echo Persisted WFP policy moved to:
  echo   %BACKUP%
)

echo.
echo GeniaFirewall.Service stopped. Dynamic WFP filters are released with the service session.
echo The persisted policy was disabled so it will not be restored on the next service start.
echo Microsoft Defender Firewall rules are NOT removed by this script.
pause
