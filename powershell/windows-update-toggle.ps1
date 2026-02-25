<#
.SYNOPSIS
    Toggle Windows Automatic Updates On or Off.

.DESCRIPTION
    This script enables or disables Windows Automatic Updates
    by modifying the following registry key:

    HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU

    -Mode Off  → Disables Automatic Updates
    -Mode On   → Enables Automatic Updates

.USAGE
    Run PowerShell as Administrator.

    Disable Updates:
        $Mode = "Off"

    Enable Updates:
        $Mode = "On"
#>

$Mode = "Off"   # Change to "On" or "Off"

# Ensure script is run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltinRole]::Administrator)) {

    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit
}

$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

# Ensure registry path exists
if (-not (Test-Path $path)) {
    New-Item -Path $path -Force | Out-Null
}

switch ($Mode) {

    "Off" {
        New-ItemProperty -Path $path `
            -Name "NoAutoUpdate" `
            -Value 1 `
            -PropertyType DWord `
            -Force | Out-Null

        Write-Host "Windows Automatic Updates have been DISABLED." -ForegroundColor Yellow
    }

    "On" {
        Remove-ItemProperty -Path $path `
            -Name "NoAutoUpdate" `
            -ErrorAction SilentlyContinue

        Write-Host "Windows Automatic Updates have been ENABLED." -ForegroundColor Green
    }
}
