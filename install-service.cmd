@echo off
setlocal
cd /d "%~dp0"

set "SERVICE_NAME=GeniaFirewallService"
set "SOURCE_EXE=%~dp0GeniaFirewall.Service.exe"
set "SERVICE_DIR=%ProgramFiles%\GeniaFirewall\Service"
set "SERVICE_EXE=%SERVICE_DIR%\GeniaFirewall.Service.exe"
set "STAGED_EXE=%SERVICE_DIR%\GeniaFirewall.Service.exe.new"

fltmc >nul 2>&1
if errorlevel 1 (
  echo ERROR: run this script as Administrator.
  pause
  exit /b 1
)

if not exist "%SOURCE_EXE%" (
  echo ERROR: %SOURCE_EXE% not found.
  echo Build/publish the portable package first.
  pause
  exit /b 1
)

echo Installing/updating %SERVICE_NAME%...
sc.exe query "%SERVICE_NAME%" >nul 2>&1
if not errorlevel 1 (
  sc.exe stop "%SERVICE_NAME%" >nul 2>&1
  powershell.exe -NoProfile -Command "$s=Get-Service -Name '%SERVICE_NAME%' -ErrorAction Stop; $s.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))"
  if errorlevel 1 goto :fail
)

if not exist "%SERVICE_DIR%" mkdir "%SERVICE_DIR%"
if errorlevel 1 goto :fail

rem The service runs as LocalSystem. Keep its binary outside the user-writable portable folder.
icacls "%SERVICE_DIR%" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" >nul
if errorlevel 1 goto :fail

copy /Y "%SOURCE_EXE%" "%STAGED_EXE%" >nul
if errorlevel 1 goto :fail
move /Y "%STAGED_EXE%" "%SERVICE_EXE%" >nul
if errorlevel 1 goto :fail

icacls "%SERVICE_EXE%" /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" >nul
if errorlevel 1 goto :fail

sc.exe query "%SERVICE_NAME%" >nul 2>&1
if not errorlevel 1 (
  sc.exe config "%SERVICE_NAME%" binPath= "\"%SERVICE_EXE%\"" start= auto depend= BFE DisplayName= "GeniaFirewall Service" >nul
  if errorlevel 1 goto :fail
) else (
  sc.exe create "%SERVICE_NAME%" binPath= "\"%SERVICE_EXE%\"" start= auto depend= BFE DisplayName= "GeniaFirewall Service" >nul
  if errorlevel 1 goto :fail
)

sc.exe description "%SERVICE_NAME%" "GeniaFirewall privileged WFP policy service." >nul
sc.exe failure "%SERVICE_NAME%" reset= 60 actions= restart/5000/restart/5000/restart/5000 >nul
sc.exe start "%SERVICE_NAME%"
if errorlevel 1 goto :fail

echo.
echo Service installed and started.
echo Protected service binary:
echo   %SERVICE_EXE%
echo The portable UI folder can be moved without changing the service path.
echo Select the backend in GeniaFirewall Settings.
echo In GeniaFirewall WFP mode, the service persists and enforces inbound/outbound policy directly.
echo GeniaFirewall 0.7.3 Stable automatically refreshes physical vs virtual/TUN interface scope.
pause
exit /b 0

:fail
echo.
echo ERROR: service installation/start failed.
sc.exe query "%SERVICE_NAME%"
pause
exit /b 1
