#requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

Write-Host 'GeniaFirewall emergency firewall cleanup' -ForegroundColor Yellow
Write-Host 'This cleanup stops GeniaFirewall.Service first so dynamic WFP filters are released,'
Write-Host 'then disables persisted GeniaFirewall WFP policy and removes only Windows Firewall rules owned by GeniaFirewall.'
Write-Host

try {
    $svc = Get-Service -Name 'GeniaFirewallService' -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') {
        Write-Host 'Stopping GeniaFirewallService to release dynamic WFP filters...'
        Stop-Service -Name 'GeniaFirewallService' -Force -ErrorAction Stop
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(10))
        Write-Host 'Service stopped; WFP dynamic session released.' -ForegroundColor Green
    }
} catch {
    Write-Warning "Could not stop GeniaFirewallService: $($_.Exception.Message)"
    $answer = Read-Host 'Continue removing compatibility rules anyway? [y/N]'
    if ($answer -notin @('y','Y')) {
        Write-Host 'Cancelled.'
        exit 1
    }
}

$policyPath = Join-Path $env:ProgramData 'GeniaFirewall\Service\wfp-policy.json'
$policyBackup = Join-Path $env:ProgramData 'GeniaFirewall\Service\wfp-policy.cleanup-backup.json'
if (Test-Path $policyPath) {
    try {
        if (Test-Path $policyBackup) { Remove-Item $policyBackup -Force }
        Move-Item $policyPath $policyBackup -Force
        Write-Host "Persisted WFP policy disabled; backup: $policyBackup" -ForegroundColor Green
    } catch {
        Write-Warning "Could not disable persisted WFP policy: $($_.Exception.Message)"
    }
}

$rules = @()
try {
    $rules += @(Get-NetFirewallRule -Group 'GeniaFirewall' -ErrorAction SilentlyContinue)
} catch {
}

try {
    $rules += @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {
        $_.DisplayName -like 'GeniaFirewall — *' -or $_.Name -like 'GeniaFirewall — *'
    })
} catch {
}

$rules = @($rules | Sort-Object InstanceID -Unique)
if ($rules.Count -eq 0) {
    Write-Host 'No GeniaFirewall Windows Firewall rules found.' -ForegroundColor Green
    exit 0
}

$rules | Select-Object DisplayName, Enabled, Direction, Action | Format-Table -AutoSize
Write-Host
$answer = Read-Host "Remove these $($rules.Count) compatibility rule(s)? [y/N]"
if ($answer -notin @('y','Y')) {
    Write-Host 'Cancelled.'
    exit 0
}

$rules | Remove-NetFirewallRule
Write-Host 'GeniaFirewall Windows Firewall rules removed.' -ForegroundColor Green
