param(
    [Parameter(Mandatory = $true)]
    [string] $LauncherPath
)
$ErrorActionPreference = 'Stop'
$exe = (Resolve-Path -LiteralPath $LauncherPath).ProviderPath
if (-not [IO.Path]::IsPathRooted($exe)) { throw 'Launcher path is not absolute.' }
$sha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash

function Assert-ExitCode([string] $label, [string] $digest, [string] $target, [int] $expected) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = ('--sha256 {0} --target "{1}"' -f $digest, $target)
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    $process = [System.Diagnostics.Process]::Start($psi)
    if ($null -eq $process) { throw "Failed to start test: $label" }
    try {
        if (-not $process.WaitForExit(15000)) {
            try { $process.Kill() } catch {}
            throw "Launcher test timed out: $label"
        }
        Write-Output ("{0}={1}" -f $label, $process.ExitCode)
        if ($process.ExitCode -ne $expected) {
            throw "$label: expected exit code $expected, got $($process.ExitCode)"
        }
    } finally {
        $process.Dispose()
    }
}

# Launching the helper itself as the valid target is safe: the child immediately
# exits because it has only --background, without creating additional processes.
# It tests the true success path while the parent still holds an open read handle.
Assert-ExitCode 'GOOD_PIN_LAUNCH' $sha $exe 0
Assert-ExitCode 'BAD_PIN_FAIL_CLOSED' ('0' * 64) $exe 21
Assert-ExitCode 'MISSING_EXE_FAIL_CLOSED' $sha (Join-Path ([IO.Path]::GetDirectoryName($exe)) 'does-not-exist.exe') 20
Write-Output 'AUTOSTART_LAUNCHER_SECURITY_SMOKE=PASS'
