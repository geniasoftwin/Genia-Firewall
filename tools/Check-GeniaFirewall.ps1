$ErrorActionPreference = 'Continue'

Write-Host '=== GeniaFirewall 0.7.3 Stable diagnostic check ===' -ForegroundColor Cyan
Write-Host ("Time: {0}" -f (Get-Date))
Write-Host

Write-Host '[Process]'
$processes = Get-Process GeniaFirewall -ErrorAction SilentlyContinue
if ($processes) {
    $processes | Select-Object Id, ProcessName, StartTime, CPU, WorkingSet64 | Format-Table -AutoSize
} else {
    Write-Host 'GeniaFirewall process not found.'
}

Write-Host '[Autostart]'
$taskName = 'GeniaFirewall Portable Autostart'
try {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
    Write-Host ("Scheduled task: {0}; State={1}" -f $task.TaskName, $task.State)
    if ($info) {
        Write-Host ("LastRun={0}; LastResult={1}; NextRun={2}" -f $info.LastRunTime, $info.LastTaskResult, $info.NextRunTime)
    }
    $task.Actions | Select-Object Execute, Arguments, WorkingDirectory | Format-List
} catch {
    Write-Host 'Scheduled task: not configured'
}

$runPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
try {
    $value = (Get-ItemProperty -Path $runPath -Name GeniaFirewall -ErrorAction Stop).GeniaFirewall
    Write-Host "Legacy Run entry still exists: $value"
} catch {
    Write-Host 'Legacy Run entry: not present'
}

Write-Host

Write-Host '[GeniaFirewall Service]'
try {
    $svc = Get-Service -Name 'GeniaFirewallService' -ErrorAction Stop
    Write-Host ("Service: {0}; StartType={1}" -f $svc.Status, $svc.StartType)
    $svcReg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\GeniaFirewallService' -ErrorAction SilentlyContinue
    if ($svcReg) {
        Write-Host ("ImagePath: {0}" -f $svcReg.ImagePath)
    }
} catch {
    Write-Host 'Service: not installed'
}
Write-Host
Write-Host '[BFE / Windows Filtering Platform]'
try {
    $bfe = Get-Service -Name BFE -ErrorAction Stop
    Write-Host ("Base Filtering Engine: {0}; StartType={1}" -f $bfe.Status, $bfe.StartType)
} catch {
    Write-Host "Could not query BFE: $($_.Exception.Message)"
}
Write-Host



Write-Host '[Network interfaces / TUN candidates]'
try {
    Get-NetAdapter -IncludeHidden -ErrorAction Stop |
        Sort-Object ifIndex |
        Select-Object ifIndex, Name, InterfaceDescription, Status, HardwareInterface |
        Format-Table -AutoSize
} catch {
    Write-Host "Could not query network adapters: $($_.Exception.Message)"
}
Write-Host

Write-Host '[Persisted WFP policy]'
$servicePolicy = Join-Path $env:ProgramData 'GeniaFirewall\Service\wfp-policy.json'
Write-Host "Policy path: $servicePolicy"
if (Test-Path $servicePolicy) {
    try {
        $policy = Get-Content $servicePolicy -Raw | ConvertFrom-Json
        Write-Host ("BackendActive={0}; Protection={1}; Mode={2}; Apps={3}" -f $policy.BackendActive, $policy.ProtectionEnabled, $policy.Mode, @($policy.Applications).Count)
    } catch {
        Write-Host "Could not parse service policy: $($_.Exception.Message)"
    }
} else {
    Write-Host 'No persisted WFP policy.'
}
Write-Host
Write-Host '[Windows Firewall rules]'
try {
    $rules = Get-NetFirewallRule -Group 'GeniaFirewall' -ErrorAction Stop
    if ($rules) {
        $rules | Select-Object DisplayName, Enabled, Direction, Action, Profile | Format-Table -AutoSize
        Write-Host ("Rule count: {0}" -f @($rules).Count)
    } else {
        Write-Host 'No GeniaFirewall rules.'
    }
} catch {
    Write-Host "Could not query rules: $($_.Exception.Message)"
}

Write-Host
Write-Host '[Portable data]'
$root = Split-Path -Parent $PSScriptRoot
$data = Join-Path $root 'Data'
Write-Host "Expected Data path: $data"
if (Test-Path $data) {
    Get-ChildItem $data -Force | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize

    $settingsFile = Join-Path $data 'settings.json'
    if (Test-Path $settingsFile) {
        try {
            $settings = Get-Content $settingsFile -Raw | ConvertFrom-Json
            Write-Host ("BackendMode={0}; Protection={1}; Mode={2}" -f $settings.BackendMode, $settings.ProtectionEnabled, $settings.Mode)
        } catch {
            Write-Host "Could not parse settings.json: $($_.Exception.Message)"
        }
    }

    $appsFile = Join-Path $data 'apps.json'
    if (Test-Path $appsFile) {
        try {
            $apps = @(Get-Content $appsFile -Raw | ConvertFrom-Json)
            $hashed = @($apps | Where-Object { $_.Sha256 -and $_.Sha256.Length -eq 64 }).Count
            $changed = @($apps | Where-Object { $_.FingerprintChanged -eq $true }).Count
            $tcp = @($apps | Where-Object { $_.SeenTcp -eq $true }).Count
            $udp = @($apps | Where-Object { $_.SeenUdp -eq $true }).Count
            Write-Host ("Apps={0}; hashed={1}; changed/quarantined={2}; TCP-seen={3}; UDP-seen={4}" -f $apps.Count, $hashed, $changed, $tcp, $udp)
        } catch {
            Write-Host "Could not parse apps.json: $($_.Exception.Message)"
        }
    }
} else {
    Write-Host 'Data folder does not exist yet.'
}

Write-Host
Write-Host '[Recent log tail]'
$logDir = Join-Path $data 'Logs'
$latest = Get-ChildItem $logDir -Filter '*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($latest) {
    Write-Host "Log: $($latest.FullName)"
    Get-Content $latest.FullName -Tail 30
} else {
    Write-Host 'No diagnostic log found.'
}

Write-Host
Write-Host 'Diagnostic check completed.' -ForegroundColor Cyan
