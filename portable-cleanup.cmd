@echo off
setlocal
cd /d "%~dp0"

echo GeniaFirewall Portable cleanup helper
echo.
echo 1. Removing the current user's GeniaFirewall autostart entry (if present)...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "GeniaFirewall" /f >nul 2>&1

echo.
echo The GeniaFirewall Windows service is NOT silently removed by this script.
echo If installed, run uninstall-service.cmd as Administrator before moving/deleting this folder.
echo.
echo Firewall rules are NOT silently removed by this script.
echo Preferred cleanup: GeniaFirewall ^> Settings ^> Emergency remove rules.
echo If the app cannot start, run tools\Remove-GeniaFirewallRules.ps1 as Administrator.
echo.
set /p ANSWER=Delete the local Data folder? [y/N]:
if /I not "%ANSWER%"=="y" goto :done
if exist ".\Data" rmdir /s /q ".\Data"
echo Data folder removed.

:done
echo Cleanup helper finished.
pause
