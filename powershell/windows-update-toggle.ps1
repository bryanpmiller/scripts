<#
.SYNOPSIS
    Toggle Windows Automatic Updates On or Off (Policy + Service).

.DESCRIPTION
    Off:
        - Sets NoAutoUpdate = 1
        - Stops wuauserv
        - Sets wuauserv StartupType to Disabled

    On:
        - Removes NoAutoUpdate
        - Sets wuauserv StartupType to Manual
        - Starts wuauserv

.NOTES
    Must be run as Administrator.


.USAGE
    Run PowerShell as Administrator.

    Disable Updates:
        $Mode = "Off"

    Enable Updates:
        $Mode = "On"
#>

$Mode = "Off"   # Change to "On" or "Off"

# Admin check
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltinRole]::Administrator)) {

    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit
}

$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$name = "NoAutoUpdate"

if (-not (Test-Path $path)) {
    New-Item -Path $path -Force | Out-Null
}

switch ($Mode) {

    "Off" {
        Write-Host "Disabling Windows Updates..." -ForegroundColor Yellow

        # Policy
        New-ItemProperty -Path $path -Name $name -Value 1 -PropertyType DWord -Force | Out-Null

        # Service
        Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
        Set-Service wuauserv -StartupType Disabled
    }

    "On" {
        Write-Host "Enabling Windows Updates..." -ForegroundColor Green

        # Policy
        Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue

        # Service
        Set-Service wuauserv -StartupType Manual
        Start-Service wuauserv -ErrorAction SilentlyContinue
    }
}

# ---- VERIFICATION ----

$policyState = if ((Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name -eq 1) {
    "Disabled"
} else {
    "Enabled"
}

$service = Get-Service wuauserv
$serviceState = $service.Status
$startupType = (Get-CimInstance Win32_Service -Filter "Name='wuauserv'").StartMode

Write-Host "`n==== Verification ====" -ForegroundColor Cyan
Write-Host "Policy State  : $policyState"
Write-Host "Service State : $serviceState"
Write-Host "Startup Type  : $startupType"
Write-Host "=======================" -ForegroundColor Cyan

Get-Service -Name wuauserv
