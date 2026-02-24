# Allow module install just for this session
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# Install PSWindowsUpdate (from PowerShell Gallery) if missing
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
  Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
  Install-Module -Name PSWindowsUpdate -Force
}

Import-Module PSWindowsUpdate

# Show what’s available
Get-WindowsUpdate

# Install ALL updates, accept prompts, reboot if needed
Install-WindowsUpdate -AcceptAll -AutoReboot
