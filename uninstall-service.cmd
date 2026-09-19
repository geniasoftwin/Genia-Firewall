@echo off
setlocal

set "SERVICE_NAME=GeniaFirewallService"
set "SERVICE_DIR=%ProgramFiles%\GeniaFirewall\Service"

fltmc >nul 2>&1
if errorlevel 1 (
  echo ERROR: run this script as Administrator.
  pause
  exit /b 1
)

sc.exe query "%SERVICE_NAME%" >nul 2>&1
if errorlevel 1 (
  echo Service is not installed.
) else (
  echo Stopping %SERVICE_NAME%...
  sc.exe stop "%SERVICE_NAME%" >nul 2>&1
  powershell.exe -NoProfile -Command "$s=Get-Service -Name '%SERVICE_NAME%' -ErrorAction SilentlyContinue; if($s){$s.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))}"
  if errorlevel 1 goto :fail

  echo Removing %SERVICE_NAME%...
  sc.exe delete "%SERVICE_NAME%"
  if errorlevel 1 goto :fail
)

if exist "%SERVICE_DIR%" (
  echo Removing protected service files...
  rmdir /s /q "%SERVICE_DIR%"
  if exist "%SERVICE_DIR%" goto :fail
)

echo.
echo Done. 0.7.3 Stable dynamic WFP objects disappear when the service session closes.
echo Persisted policy remains under %%ProgramData%%\GeniaFirewall\Service unless removed manually.
pause
exit /b 0

:fail
echo.
echo ERROR: could not fully stop or remove the service.
sc.exe query "%SERVICE_NAME%"
pause
exit /b 1
