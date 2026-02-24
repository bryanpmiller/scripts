# PowerShell script to upgrade curl and Git, then display curl version

Write-Host "Starting upgrades..." -ForegroundColor Cyan
Write-Host ""

# Upgrade curl
Write-Host "Upgrading curl..." -ForegroundColor Yellow
winget upgrade curl

# Upgrade Git
Write-Host ""
Write-Host "Upgrading Git..." -ForegroundColor Yellow
winget upgrade Git.Git

# Display completion message and curl version
Write-Host ""
Write-Host "✅ Upgrades complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Current curl version:" -ForegroundColor Cyan
curl.exe --version
