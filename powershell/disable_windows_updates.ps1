# Disable automatic updates
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
if (-not (Test-Path $path)) {
    New-Item -Path $path -Force | Out-Null
}
New-ItemProperty -Path $path -Name "NoAutoUpdate" -Value 1 -PropertyType DWord -Force | Out-Null

Write-Host "Windows Updates have been disabled" -ForegroundColor Yellow
