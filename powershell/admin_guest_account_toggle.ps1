#requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =========================
# Local Account Setup Toggle (NAME-based: Administrator + Guest)
# =========================
# WARNING: INSECURE — FOR LAB USE ONLY

# >>> EDIT THESE <<<
# "On" = Admin & Guest accounts activated/added to admin group
# "Off" = Removes Admin account / disables guest / removes group priv

$Toggle = "On"  

$AdministratorPasswordPlain = ""   # "" = none (often blocked)
$GuestPasswordPlain         = ""   # "" = none (often blocked)

# -------------------------
# Helpers
# -------------------------
function Add-Line {
    param([ref]$Report, [string]$Text)
    $Report.Value += $Text
}

function Try-Step {
    param([ref]$Report, [string]$Label, [scriptblock]$Action)

    try {
        & $Action
        Add-Line -Report $Report -Text "✅ $Label"
        return $true
    } catch {
        Add-Line -Report $Report -Text "❌ $Label — $($_.Exception.Message)"
        return $false
    }
}

function Get-AdministratorsGroupName {
    # Local Administrators group SID ends with -544 (S-1-5-32-544)
    $g = Get-LocalGroup | Where-Object { $_.SID.Value -match '-544$' } | Select-Object -First 1
    if (-not $g) { throw "Could not find local Administrators group (SID ...-544)." }
    return $g.Name
}

function Test-IsBuiltInAdministrator {
    param([string]$Name)

    # Built-in local Administrator is RID 500: S-1-5-21-...-500
    try {
        $u = Get-LocalUser -Name $Name -ErrorAction Stop
        return ($u.SID.Value -match '-500$')
    } catch {
        return $false
    }
}

function Ensure-UserByName {
    param(
        [string]$Name,
        [string]$PasswordPlain,
        [string]$AdminsGroupName,
        [ref]$Report
    )

    $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue

    if (-not $user) {
        Add-Line -Report $Report -Text "• $Name account did not exist."

        if ([string]::IsNullOrEmpty($PasswordPlain)) {
            Try-Step -Report $Report -Label "Created $Name account with no password." -Action {
                New-LocalUser -Name $Name -NoPassword -Description "$Name (created by script)" | Out-Null
            } | Out-Null
        } else {
            $sec = ConvertTo-SecureString $PasswordPlain -AsPlainText -Force
            Try-Step -Report $Report -Label "Created $Name account (password set)." -Action {
                New-LocalUser -Name $Name -Password $sec -Description "$Name (created by script)" | Out-Null
            } | Out-Null
        }

        $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
        if (-not $user) {
            Add-Line -Report $Report -Text "❌ $Name still not present after creation attempt."
            return
        }
    } else {
        Add-Line -Report $Report -Text "• $Name account exists."
    }

    # Enable (try cmdlet then fallback net user)
    $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    if ($user.Enabled) {
        Add-Line -Report $Report -Text "✅ $Name already enabled."
    } else {
        Try-Step -Report $Report -Label "Enabled $Name (Enable-LocalUser)." -Action {
            Enable-LocalUser -Name $Name
        } | Out-Null

        $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
        if (-not $user.Enabled) {
            Try-Step -Report $Report -Label "Enabled $Name (net user /active:yes fallback)." -Action {
                cmd.exe /c "net user `"$Name`" /active:yes" | Out-Null
            } | Out-Null
        }

        $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
        if ($user.Enabled) {
            Add-Line -Report $Report -Text "✅ $Name enabled (verified)."
        } else {
            Add-Line -Report $Report -Text "❌ $Name still disabled after attempts (likely Local Security Policy/GPO)."
        }
    }

    # Set password
    if ([string]::IsNullOrEmpty($PasswordPlain)) {
        Try-Step -Report $Report -Label "Set password to (none)." -Action {
            # net user is the most tolerant way to attempt blank
            cmd.exe /c "net user `"$Name`" `"`"" | Out-Null
        } | Out-Null
    } else {
        $sec2 = ConvertTo-SecureString $PasswordPlain -AsPlainText -Force
        Try-Step -Report $Report -Label "Set password to (password set)." -Action {
            Set-LocalUser -Name $Name -Password $sec2
        } | Out-Null
    }

    # Add to local Administrators group (try cmdlet, verify, fallback net localgroup)
    Try-Step -Report $Report -Label "Add to '$AdminsGroupName' (Add-LocalGroupMember)." -Action {
        Add-LocalGroupMember -Group $AdminsGroupName -Member $Name -ErrorAction Stop
    } | Out-Null

    $isMember = $false
    try {
        $members = Get-LocalGroupMember -Group $AdminsGroupName -ErrorAction Stop
        $isMember = $members.Name -match "(^|\\)$([regex]::Escape($Name))$"
    } catch { }

    if (-not $isMember) {
        Try-Step -Report $Report -Label "Add to '$AdminsGroupName' (net localgroup fallback)." -Action {
            cmd.exe /c "net localgroup `"$AdminsGroupName`" `"$Name`" /add" | Out-Null
        } | Out-Null
    }

    # Final membership verify
    $isMember = $false
    try {
        $members = Get-LocalGroupMember -Group $AdminsGroupName -ErrorAction Stop
        $isMember = $members.Name -match "(^|\\)$([regex]::Escape($Name))$"
    } catch { }

    if ($isMember) {
        Add-Line -Report $Report -Text "✅ $Name is in '$AdminsGroupName' (verified)."
    } else {
        Add-Line -Report $Report -Text "❌ $Name is NOT in '$AdminsGroupName' after attempts."
    }
}

function Remove-UserByNameIfSafe {
    param(
        [string]$Name,
        [ref]$Report
    )

    $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    if (-not $user) {
        Add-Line -Report $Report -Text "• $Name does not exist (nothing to delete)."
        return
    }

    if (Test-IsBuiltInAdministrator -Name $Name) {
        Add-Line -Report $Report -Text "⚠️ $Name is the built-in Administrator (RID 500). Skipping delete for safety/compatibility."
        return
    }

    Try-Step -Report $Report -Label "Deleted local user '$Name'." -Action {
        Remove-LocalUser -Name $Name -ErrorAction Stop
    } | Out-Null
}

function Remove-From-Admins {
    param(
        [string]$Name,
        [string]$AdminsGroupName,
        [ref]$Report
    )

    # Try cmdlet remove, then fallback net localgroup
    Try-Step -Report $Report -Label "Remove '$Name' from '$AdminsGroupName' (Remove-LocalGroupMember)." -Action {
        Remove-LocalGroupMember -Group $AdminsGroupName -Member $Name -ErrorAction Stop
    } | Out-Null

    Try-Step -Report $Report -Label "Remove '$Name' from '$AdminsGroupName' (net localgroup fallback)." -Action {
        cmd.exe /c "net localgroup `"$AdminsGroupName`" `"$Name`" /delete" | Out-Null
    } | Out-Null
}

function Disable-UserByName {
    param(
        [string]$Name,
        [ref]$Report
    )

    $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    if (-not $user) {
        Add-Line -Report $Report -Text "• $Name does not exist (nothing to disable)."
        return
    }

    if (-not $user.Enabled) {
        Add-Line -Report $Report -Text "✅ $Name already disabled."
        return
    }

    Try-Step -Report $Report -Label "Disabled $Name (Disable-LocalUser)." -Action {
        Disable-LocalUser -Name $Name
    } | Out-Null

    $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    if ($user.Enabled) {
        Try-Step -Report $Report -Label "Disabled $Name (net user /active:no fallback)." -Action {
            cmd.exe /c "net user `"$Name`" /active:no" | Out-Null
        } | Out-Null
    }

    $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    if (-not $user.Enabled) {
        Add-Line -Report $Report -Text "✅ $Name disabled (verified)."
    } else {
        Add-Line -Report $Report -Text "❌ $Name still enabled after attempts (likely Local Security Policy/GPO)."
    }
}

# -------------------------
# Context + Run
# -------------------------
$limitBlank = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LimitBlankPasswordUse -ErrorAction SilentlyContinue).LimitBlankPasswordUse
$policyNote = if ($null -eq $limitBlank) {
    "LimitBlankPasswordUse not found (policy may still exist elsewhere)."
} else {
    "LimitBlankPasswordUse = $limitBlank (1 = blank passwords restricted)."
}

$adminsGroupName = Get-AdministratorsGroupName

$adminReport = @()
$guestReport = @()

if ($Toggle -eq "On") {
    Ensure-UserByName -Name "Administrator" -PasswordPlain $AdministratorPasswordPlain -AdminsGroupName $adminsGroupName -Report ([ref]$adminReport)
    Ensure-UserByName -Name "Guest"         -PasswordPlain $GuestPasswordPlain         -AdminsGroupName $adminsGroupName -Report ([ref]$guestReport)
}
elseif ($Toggle -eq "Off") {
    # OFF = opposite
    # - Delete Administrator account (only if it's NOT the built-in RID 500 account)
    Remove-UserByNameIfSafe -Name "Administrator" -Report ([ref]$adminReport)

    # - Remove Guest from Administrators group
    Remove-From-Admins -Name "Guest" -AdminsGroupName $adminsGroupName -Report ([ref]$guestReport)

    # - Disable Guest account
    Disable-UserByName -Name "Guest" -Report ([ref]$guestReport)
}
else {
    throw "Invalid Toggle value: '$Toggle'. Use 'On' or 'Off'."
}

# -------------------------
# Clean Summary
# -------------------------
Write-Host "`n==================== CLEAN SUMMARY ====================" -ForegroundColor Yellow
Write-Host $policyNote -ForegroundColor DarkYellow
Write-Host "Administrators group resolved as: '$adminsGroupName'" -ForegroundColor DarkYellow
Write-Host "Toggle mode: $Toggle" -ForegroundColor DarkYellow

Write-Host "`n--- Administrator ---" -ForegroundColor Cyan
$adminReport | ForEach-Object { Write-Host $_ }

Write-Host "`n--- Guest ---" -ForegroundColor Cyan
$guestReport | ForEach-Object { Write-Host $_ }

Write-Host "`n--- Verification: Users (authoritative) ---" -ForegroundColor Yellow
Get-LocalUser -Name "Administrator","Guest" -ErrorAction SilentlyContinue |
    Select Name, Enabled, PasswordRequired, PasswordExpires, LastLogon, SID |
    Format-Table -AutoSize

Write-Host "`n--- Verification: '$adminsGroupName' Members (filtered) ---" -ForegroundColor Yellow
Get-LocalGroupMember -Group $adminsGroupName -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match "(^|\\)Administrator$" -or $_.Name -match "(^|\\)Guest$" } |
    Format-Table -AutoSize

Write-Host "`nDone." -ForegroundColor Green
