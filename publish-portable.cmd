@echo off
setlocal
cd /d "%~dp0"

set "OUT=.\publish\GeniaFirewall-0.7.3-Stable-win-x64"
set "ZIP=.\publish\GeniaFirewall-0.7.3-Stable-Portable-win-x64.zip"
set "SHA=.\publish\GeniaFirewall-0.7.3-Stable-SHA256.txt"
set "UI_PROJECT=.\GeniaFirewall\GeniaFirewall.csproj"
set "SERVICE_PROJECT=.\GeniaFirewall.Service\GeniaFirewall.Service.csproj"
set "PROTOCOL_PROJECT=.\GeniaFirewall.Protocol\GeniaFirewall.Protocol.csproj"
set "MANIFEST=.\GeniaFirewall\app.manifest"
set "SERVICE_MANIFEST=.\GeniaFirewall.Service\app.manifest"

echo Checking GeniaFirewall 0.7.3 Stable version metadata...
findstr /L /C:"0.7.3.4" "%MANIFEST%" >nul || goto :version_error
findstr /L /C:"0.7.3.4" "%SERVICE_MANIFEST%" >nul || goto :version_error
findstr /L /C:"<Version>0.7.3.4</Version>" "%UI_PROJECT%" >nul || goto :version_error
findstr /L /C:"<AssemblyVersion>0.7.3.4</AssemblyVersion>" "%UI_PROJECT%" >nul || goto :version_error
findstr /L /C:"<FileVersion>0.7.3.4</FileVersion>" "%UI_PROJECT%" >nul || goto :version_error
findstr /L /C:"<Version>0.7.3.4</Version>" "%SERVICE_PROJECT%" >nul || goto :version_error
findstr /L /C:"<AssemblyVersion>0.7.3.4</AssemblyVersion>" "%SERVICE_PROJECT%" >nul || goto :version_error
findstr /L /C:"<FileVersion>0.7.3.4</FileVersion>" "%SERVICE_PROJECT%" >nul || goto :version_error
findstr /L /C:"<Version>0.7.3.4</Version>" "%PROTOCOL_PROJECT%" >nul || goto :version_error

echo Cleaning stale bin/obj and old publish output...
for %%D in (".\GeniaFirewall\bin" ".\GeniaFirewall\obj" ".\GeniaFirewall.Service\bin" ".\GeniaFirewall.Service\obj" ".\GeniaFirewall.Protocol\bin" ".\GeniaFirewall.Protocol\obj") do (
  if exist %%~D rmdir /s /q %%~D
)
if exist "%OUT%" rmdir /s /q "%OUT%"
if exist "%ZIP%" del /q "%ZIP%"
if exist "%SHA%" del /q "%SHA%"

echo.
echo [1/2] Publishing GeniaFirewall UI 0.7.3 Stable Portable win-x64...
dotnet publish "%UI_PROJECT%" ^
  -c Release ^
  -r win-x64 ^
  --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:IncludeNativeLibrariesForSelfExtract=true ^
  -p:EnableCompressionInSingleFile=true ^
  -p:PublishTrimmed=false ^
  -p:DebugType=None ^
  -p:DebugSymbols=false ^
  -o "%OUT%"
if errorlevel 1 goto :publish_error

echo.
echo [2/2] Publishing GeniaFirewall.Service 0.7.3 Stable win-x64...
dotnet publish "%SERVICE_PROJECT%" ^
  -c Release ^
  -r win-x64 ^
  --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:IncludeNativeLibrariesForSelfExtract=true ^
  -p:EnableCompressionInSingleFile=true ^
  -p:PublishTrimmed=false ^
  -p:DebugType=None ^
  -p:DebugSymbols=false ^
  -o "%OUT%"
if errorlevel 1 goto :publish_error

if not exist "%OUT%\GeniaFirewall.exe" goto :publish_error
if not exist "%OUT%\GeniaFirewall.Service.exe" goto :publish_error

echo Verifying published file versions...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$expected='0.7.3.4'; $files=@('%OUT%\GeniaFirewall.exe','%OUT%\GeniaFirewall.Service.exe'); foreach($file in $files){$actual=(Get-Item -LiteralPath $file).VersionInfo.FileVersion; if($actual -ne $expected){Write-Error ('Version mismatch: {0} is {1}, expected {2}' -f $file,$actual,$expected); exit 1}}"
if errorlevel 1 goto :version_error

copy /Y ".\install-service.cmd" "%OUT%\install-service.cmd" >nul
copy /Y ".\uninstall-service.cmd" "%OUT%\uninstall-service.cmd" >nul
copy /Y ".\service-console.cmd" "%OUT%\service-console.cmd" >nul
copy /Y ".\emergency-stop-wfp.cmd" "%OUT%\emergency-stop-wfp.cmd" >nul

if exist ".\tools" (
  if not exist "%OUT%\tools" mkdir "%OUT%\tools"
  copy /Y ".\tools\Check-GeniaFirewall.ps1" "%OUT%\tools\Check-GeniaFirewall.ps1" >nul
  copy /Y ".\tools\Remove-GeniaFirewallRules.ps1" "%OUT%\tools\Remove-GeniaFirewallRules.ps1" >nul
)

echo.
echo Creating portable ZIP...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Compress-Archive -Path '%OUT%\*' -DestinationPath '%ZIP%' -Force"
if errorlevel 1 goto :package_error
if not exist "%ZIP%" goto :package_error

for %%F in ("%ZIP%") do set "ZIP_NAME=%%~nxF"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$hash=(Get-FileHash -LiteralPath '%ZIP%' -Algorithm SHA256).Hash.ToLowerInvariant(); ($hash + '  %ZIP_NAME%') | Set-Content -LiteralPath '%SHA%' -Encoding ASCII"
if errorlevel 1 goto :package_error
if not exist "%SHA%" goto :package_error

echo.
echo Done:
echo   %OUT%\GeniaFirewall.exe
echo   %OUT%\GeniaFirewall.Service.exe
echo   %OUT%\install-service.cmd
echo   %OUT%\emergency-stop-wfp.cmd
echo   %ZIP%
echo   %SHA%
echo.
echo Version: 0.7.3.4
pause
exit /b 0

:version_error
echo ERROR: one or more GeniaFirewall 0.7.3 Stable / 0.7.3.4 version markers are missing or published versions do not match.
pause
exit /b 1

:publish_error
echo.
echo Publish failed.
pause
exit /b 1

:package_error
echo.
echo Packaging or SHA-256 generation failed.
pause
exit /b 1
