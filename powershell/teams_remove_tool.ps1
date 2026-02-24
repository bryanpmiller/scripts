# ============================================
# Microsoft Teams Full Removal Script (Win 11)
# - Removes NEW Teams (MSIX/Appx: MSTeams / ms-teams.exe)
# - Removes CLASSIC Teams (per-user Teams.exe)
# - Cleans shortcuts + leftover folders
# - Verifies removal
# ==============================================
# README NOTES FOR USE
# - You may need teams file path. If so use the following to identify then replace the file path in this script.
# - Get-AppxPackage *MSTeams* | Select Name, InstallLocation
# ============================================

$ErrorActionPreference = "SilentlyContinue"

function Stop-TeamsProcesses {
  Write-Host "Stopping Teams processes..." -ForegroundColor Cyan
  Get-Process "ms-teams","teams","Teams","Update","Squirrel" -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
}

function Remove-NewTeamsAppx {
  Write-Host "Removing NEW Microsoft Teams (MSIX/Appx)..." -ForegroundColor Cyan

  # Remove for all users (admin)
  $pkgsAll = Get-AppxPackage -AllUsers *MSTeams*
  if ($pkgsAll) {
    foreach ($p in $pkgsAll) {
      Write-Host "→ Removing (AllUsers): $($p.PackageFullName)" -ForegroundColor Yellow
      Remove-AppxPackage -AllUsers -Package $p.PackageFullName -ErrorAction SilentlyContinue
    }
  } else {
    Write-Host "→ No AllUsers MSTeams package found." -ForegroundColor DarkGray
  }

  # Remove for current user (in case -AllUsers isn't supported/allowed on this build)
  $pkgsMe = Get-AppxPackage *MSTeams*
  if ($pkgsMe) {
    foreach ($p in $pkgsMe) {
      Write-Host "→ Removing (CurrentUser): $($p.PackageFullName)" -ForegroundColor Yellow
      Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
    }
  } else {
    Write-Host "→ No current-user MSTeams package found." -ForegroundColor DarkGray
  }

  # Optional: provisioned package removal (prevents it from being auto-installed for NEW user profiles)
  Write-Host "Checking for provisioned Teams package (preinstall)..." -ForegroundColor Cyan
  $prov = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*MSTeams*" -or $_.PackageName -like "*MSTeams*" }
  if ($prov) {
    foreach ($p in $prov) {
      Write-Host "→ Removing provisioned package: $($p.PackageName)" -ForegroundColor Yellow
      Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction SilentlyContinue | Out-Null
    }
  } else {
    Write-Host "→ No provisioned MSTeams package found." -ForegroundColor DarkGray
  }
}

function Uninstall-ClassicTeams {
  Write-Host "Uninstalling CLASSIC Teams (per-user) if present..." -ForegroundColor Cyan

  # Find classic Teams uninstallers (common paths)
  $classicUninstallers = @()

  # Teams Machine-Wide Installer (sometimes present)
  $classicUninstallers += Get-ItemProperty `
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "*Teams Machine-Wide Installer*" } |
    Select-Object -ExpandProperty UninstallString

  # Per-user classic Teams (Squirrel)
  $classicUninstallers += Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Teams\Update.exe" -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty FullName

  # Execute uninstallers
  foreach ($u in $classicUninstallers | Sort-Object -Unique) {
    if (-not $u) { continue }

    if ($u -like "*Update.exe") {
      Write-Host "→ Running: $u --uninstall /s" -ForegroundColor Yellow
      Start-Process $u -ArgumentList "--uninstall /s" -Wait -ErrorAction SilentlyContinue
    } else {
      # Registry uninstall strings can be quoted and may contain args; run via cmd to preserve formatting
      Write-Host "→ Running uninstall string: $u" -ForegroundColor Yellow
      Start-Process "cmd.exe" -ArgumentList "/c $u" -Wait -ErrorAction SilentlyContinue
    }
  }
}

function Cleanup-TeamsLeftovers {
  Write-Host "Cleaning leftover folders + shortcuts..." -ForegroundColor Cyan

  # Common classic Teams leftovers
  $paths = @(
    "$env:ProgramData\Microsoft\Teams",
    "$env:ProgramFiles\Microsoft\Teams",
    "${env:ProgramFiles(x86)}\Microsoft\Teams"
  )

  # Per-user leftovers
  $paths += Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    @(
      "$($_.FullName)\AppData\Local\Microsoft\Teams",
      "$($_.FullName)\AppData\Roaming\Microsoft\Teams",
      "$($_.FullName)\AppData\Local\Microsoft\TeamsMeetingAddin",
      "$($_.FullName)\AppData\Roaming\Microsoft\TeamsMeetingAddin"
    )
  }

  foreach ($p in $paths | Sort-Object -Unique) {
    if (Test-Path $p) {
      Write-Host "→ Deleting: $p" -ForegroundColor Yellow
      Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  # Start Menu shortcuts (best-effort)
  $shortcutRoots = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
    "$env:AppData\Microsoft\Windows\Start Menu\Programs"
  )

  foreach ($root in $shortcutRoots) {
    if (Test-Path $root) {
      Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*Teams*" } |
        ForEach-Object {
          Write-Host "→ Removing shortcut/item: $($_.FullName)" -ForegroundColor DarkYellow
          Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }
  }
}

function Verify-TeamsRemoval {
  Write-Host "`nVerifying Teams removal..." -ForegroundColor Cyan

  $procs = Get-Process "ms-teams","teams" -ErrorAction SilentlyContinue
  if ($procs) {
    Write-Host "❌ Teams process still running:" -ForegroundColor Red
    $procs | Select Name, Id, Path | Format-Table -AutoSize
  } else {
    Write-Host "✅ No Teams processes running." -ForegroundColor Green
  }

  $appx = Get-AppxPackage *MSTeams* -ErrorAction SilentlyContinue
  $appxAll = Get-AppxPackage -AllUsers *MSTeams* -ErrorAction SilentlyContinue
  if ($appx -or $appxAll) {
    Write-Host "❌ MSTeams Appx package still present:" -ForegroundColor Red
    ($appx + $appxAll) | Select Name, PackageFullName, InstallLocation | Sort-Object PackageFullName -Unique | Format-Table -AutoSize
  } else {
    Write-Host "✅ MSTeams Appx package not found." -ForegroundColor Green
  }

  $exeHits = Get-ChildItem "C:\" -Filter "ms-teams.exe" -Recurse -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty FullName
  $exeHits += Get-ChildItem "C:\" -Filter "Teams.exe" -Recurse -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty FullName
  $exeHits = $exeHits | Sort-Object -Unique

  if ($exeHits.Count -gt 0) {
    Write-Host "⚠️ Executables still found (may include installer caches):" -ForegroundColor Yellow
    $exeHits
  } else {
    Write-Host "✅ No Teams executables found via broad search." -ForegroundColor Green
  }
}

# =======================
# Main
# =======================
Stop-TeamsProcesses
Remove-NewTeamsAppx
Uninstall-ClassicTeams
Cleanup-TeamsLeftovers
Verify-TeamsRemoval

Write-Host "`nDone." -ForegroundColor Cyan
