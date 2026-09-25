@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "VERSION=0.7.4.0"
set "LABEL=0.7.4-RC1"
set "OUT=.\publish\GeniaFirewall-%LABEL%-win-x64"
set "SERVICE_STAGE=.\publish\.service-%LABEL%-win-x64"
set "ZIP=.\publish\GeniaFirewall-%LABEL%-SingleExe-Portable-win-x64.zip"
set "SHA=.\publish\GeniaFirewall-%LABEL%-SHA256.txt"
set "UI_PROJECT=.\GeniaFirewall\GeniaFirewall.csproj"
set "SERVICE_PROJECT=.\GeniaFirewall.Service\GeniaFirewall.Service.csproj"
set "PROTOCOL_PROJECT=.\GeniaFirewall.Protocol\GeniaFirewall.Protocol.csproj"
set "MANIFEST=.\GeniaFirewall\app.manifest"
set "SERVICE_MANIFEST=.\GeniaFirewall.Service\app.manifest"

echo Checking GeniaFirewall %LABEL% version metadata...
findstr /L /C:"%VERSION%" "%MANIFEST%" >nul || goto :version_error
findstr /L /C:"%VERSION%" "%SERVICE_MANIFEST%" >nul || goto :version_error
findstr /L /C:"<Version>%VERSION%</Version>" "%UI_PROJECT%" >nul || goto :version_error
findstr /L /C:"<AssemblyVersion>%VERSION%</AssemblyVersion>" "%UI_PROJECT%" >nul || goto :version_error
findstr /L /C:"<FileVersion>%VERSION%</FileVersion>" "%UI_PROJECT%" >nul || goto :version_error
findstr /L /C:"<Version>%VERSION%</Version>" "%SERVICE_PROJECT%" >nul || goto :version_error
findstr /L /C:"<AssemblyVersion>%VERSION%</AssemblyVersion>" "%SERVICE_PROJECT%" >nul || goto :version_error
findstr /L /C:"<FileVersion>%VERSION%</FileVersion>" "%SERVICE_PROJECT%" >nul || goto :version_error
findstr /L /C:"<Version>%VERSION%</Version>" "%PROTOCOL_PROJECT%" >nul || goto :version_error

echo Cleaning stale bin/obj and old publish output...
for %%D in (".\GeniaFirewall\bin" ".\GeniaFirewall\obj" ".\GeniaFirewall.Service\bin" ".\GeniaFirewall.Service\obj" ".\GeniaFirewall.Protocol\bin" ".\GeniaFirewall.Protocol\obj") do (
  if exist %%~D rmdir /s /q %%~D
)
if exist "%OUT%" rmdir /s /q "%OUT%"
if exist "%SERVICE_STAGE%" rmdir /s /q "%SERVICE_STAGE%"
if exist "%ZIP%" del /q "%ZIP%"
if exist "%SHA%" del /q "%SHA%"
if not exist ".\publish" mkdir ".\publish"

echo.
echo [1/2] Publishing the embedded GeniaFirewall.Service payload...
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
  -o "%SERVICE_STAGE%"
if errorlevel 1 goto :publish_error
if not exist "%SERVICE_STAGE%\GeniaFirewall.Service.exe" goto :publish_error

for %%F in ("%SERVICE_STAGE%\GeniaFirewall.Service.exe") do set "EMBEDDED_SERVICE=%%~fF"

echo.
echo [2/2] Publishing the single-EXE GeniaFirewall portable UI...
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
  "-p:EmbeddedServicePath=%EMBEDDED_SERVICE%" ^
  -p:RequireEmbeddedService=true ^
  -o "%OUT%"
if errorlevel 1 goto :publish_error

if not exist "%OUT%\GeniaFirewall.exe" goto :publish_error

echo Verifying published versions and one-file layout...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$expected='%VERSION%'; $files=@('%OUT%\GeniaFirewall.exe','%SERVICE_STAGE%\GeniaFirewall.Service.exe'); foreach($file in $files){$actual=(Get-Item -LiteralPath $file).VersionInfo.FileVersion; if($actual -ne $expected){Write-Error ('Version mismatch: {0} is {1}, expected {2}' -f $file,$actual,$expected); exit 1}}; $items=@(Get-ChildItem -LiteralPath '%OUT%' -Force); if($items.Count -ne 1 -or $items[0].Name -ne 'GeniaFirewall.exe'){Write-Error ('Portable output must contain exactly one file; found: ' + (($items | ForEach-Object Name) -join ', ')); exit 1}"
if errorlevel 1 goto :layout_error

rmdir /s /q "%SERVICE_STAGE%"

echo.
echo Creating one-file portable ZIP...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Compress-Archive -LiteralPath '%OUT%\GeniaFirewall.exe' -DestinationPath '%ZIP%' -Force"
if errorlevel 1 goto :package_error
if not exist "%ZIP%" goto :package_error

for %%F in ("%ZIP%") do set "ZIP_NAME=%%~nxF"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$hash=(Get-FileHash -LiteralPath '%ZIP%' -Algorithm SHA256).Hash.ToLowerInvariant(); ($hash + '  %ZIP_NAME%') | Set-Content -LiteralPath '%SHA%' -Encoding ASCII"
if errorlevel 1 goto :package_error
if not exist "%SHA%" goto :package_error

echo.
echo Done. The portable directory contains exactly one user-facing file:
echo   %OUT%\GeniaFirewall.exe
echo.
echo Package:
echo   %ZIP%
echo   %SHA%
echo.
echo Version: %VERSION% (%LABEL%)
exit /b 0

:version_error
echo ERROR: one or more %LABEL% / %VERSION% version markers are missing.
exit /b 1

:layout_error
echo ERROR: portable output contains unexpected files.
exit /b 1

:publish_error
echo ERROR: publish failed.
exit /b 1

:package_error
echo ERROR: packaging or SHA-256 generation failed.
exit /b 1
