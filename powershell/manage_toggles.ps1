<#
.SYNOPSIS
    Interactive manager for toggling security settings and uninstalling Wireshark.

.DESCRIPTION
    This script combines four existing helpers into a single interactive tool. 
        - Protocol Toggle: Enables or disables SSL/TLS protocols based on user choice.
        - Cipher Suites Toggle: Configures the system's cipher suites to a secure or insecure set based on user choice.
        - Wireshark Uninstaller: Offers the option to uninstall Wireshark if it is installed.
        - Admin/Guest Account Toggle: Toggles local Administrator/Guest behavior for lab-style scenarios.
    
    For each of the toggle scripts (protocols, cipher suites, and admin/guest accounts) the user is prompted whether to run
    it and, if so, whether to configure the machine in a "secure" or "insecure" state.
    The Wireshark uninstaller can be run independently.

.NOTES
    Author        : Bryan Miller (based on original scripts by Josh Madakor)
    Date Created  : 2026-02-27
    Version       : 1.0
    Tested        : Yes

#>

# -- helper functions imported from the original scripts ------------------------------------------------

function Test-Admin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# generic helper used by the protocol and cipher routines - writes a dword and verifies it
function Set-RegistryDword {
    param(
        [string]$Path,
        [string]$Name,
        [int]$Value
    )
    New-Item -Path $Path -Force | Out-Null
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType 'DWord' -Force | Out-Null
    return (Get-ItemProperty -Path $Path -Name $Name).$Name -eq $Value
}

# protocol toggle logic extracted from protocol_toggle.ps1, parameterized
function Set-ProtocolSecurity {
    param(
        [bool]$secureEnvironment
    )

    # helper routines inside this function to keep callers simple
    function Apply-ProtocolValue {
        param($Path,$Name,$Value)
        return Set-RegistryDword -Path $Path -Name $Name -Value $Value
    }

    function Configure-Protocol {
        param(
            [string]$ServerPath,
            [string]$ClientPath,
            [int]$EnabledValue,
            [int]$DisabledByDefaultValue
        )
        $s1 = Apply-ProtocolValue -Path $ServerPath -Name 'Enabled' -Value $EnabledValue
        $s2 = Apply-ProtocolValue -Path $ServerPath -Name 'DisabledByDefault' -Value $DisabledByDefaultValue
        $s3 = Apply-ProtocolValue -Path $ClientPath -Name 'Enabled' -Value $EnabledValue
        $s4 = Apply-ProtocolValue -Path $ClientPath -Name 'DisabledByDefault' -Value $DisabledByDefaultValue
        return ($s1 -and $s2 -and $s3 -and $s4)
    }

    # SSL 2.0 paths
    $serverPathSSL2 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
    $clientPathSSL2 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"

    if ($secureEnvironment) {
        if (Configure-Protocol -ServerPath $serverPathSSL2 -ClientPath $clientPathSSL2 -EnabledValue 0 -DisabledByDefaultValue 1) {
            Write-Host "SSL 2.0 has been disabled."
        } else {
            Write-Warning "Failed to disable SSL 2.0; registry values may not match expected."
        }
    } else {
        if (Configure-Protocol -ServerPath $serverPathSSL2 -ClientPath $clientPathSSL2 -EnabledValue 1 -DisabledByDefaultValue 0) {
            Write-Host "SSL 2.0 has been enabled."
        } else {
            Write-Warning "Failed to enable SSL 2.0; registry values may not match expected."
        }
    }

    # SSL 3.0
    $serverPathSSL3 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
    $clientPathSSL3 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"

    if ($secureEnvironment) {
        if (Configure-Protocol -ServerPath $serverPathSSL3 -ClientPath $clientPathSSL3 -EnabledValue 0 -DisabledByDefaultValue 1) {
            Write-Host "SSL 3.0 has been disabled."
        } else {
            Write-Warning "Failed to disable SSL 3.0; registry values may not match expected."
        }
    } else {
        if (Configure-Protocol -ServerPath $serverPathSSL3 -ClientPath $clientPathSSL3 -EnabledValue 1 -DisabledByDefaultValue 0) {
            Write-Host "SSL 3.0 has been enabled."
        } else {
            Write-Warning "Failed to enable SSL 3.0; registry values may not match expected."
        }
    }

    # TLS 1.0
    $serverPathTLS10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
    $clientPathTLS10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"

    if ($secureEnvironment) {
        if (Configure-Protocol -ServerPath $serverPathTLS10 -ClientPath $clientPathTLS10 -EnabledValue 0 -DisabledByDefaultValue 1) {
            Write-Host "TLS 1.0 has been disabled."
        } else {
            Write-Warning "Failed to disable TLS 1.0; registry values may not match expected."
        }
    } else {
        if (Configure-Protocol -ServerPath $serverPathTLS10 -ClientPath $clientPathTLS10 -EnabledValue 1 -DisabledByDefaultValue 0) {
            Write-Host "TLS 1.0 has been enabled."
        } else {
            Write-Warning "Failed to enable TLS 1.0; registry values may not match expected."
        }
    }

    # TLS 1.1
    $serverPathTLS11 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
    $clientPathTLS11 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"

    if ($secureEnvironment) {
        if (Configure-Protocol -ServerPath $serverPathTLS11 -ClientPath $clientPathTLS11 -EnabledValue 0 -DisabledByDefaultValue 1) {
            Write-Host "TLS 1.1 has been disabled."
        } else {
            Write-Warning "Failed to disable TLS 1.1; registry values may not match expected."
        }
    } else {
        if (Configure-Protocol -ServerPath $serverPathTLS11 -ClientPath $clientPathTLS11 -EnabledValue 1 -DisabledByDefaultValue 0) {
            Write-Host "TLS 1.1 has been enabled."
        } else {
            Write-Warning "Failed to enable TLS 1.1; registry values may not match expected."
        }
    }

    # TLS 1.2
    $serverPathTLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
    $clientPathTLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"

    if ($secureEnvironment) {
        if (Configure-Protocol -ServerPath $serverPathTLS12 -ClientPath $clientPathTLS12 -EnabledValue 1 -DisabledByDefaultValue 0) {
            Write-Host "TLS 1.2 has been enabled."
        } else {
            Write-Warning "Failed to enable TLS 1.2; registry values may not match expected."
        }
    } else {
        if (Configure-Protocol -ServerPath $serverPathTLS12 -ClientPath $clientPathTLS12 -EnabledValue 0 -DisabledByDefaultValue 1) {
            Write-Host "TLS 1.2 has been disabled."
        } else {
            Write-Warning "Failed to disable TLS 1.2; registry values may not match expected."
        }
    }

    Write-Host "Please reboot for settings to take effect."
}

# cipher suites toggle logic extracted and parameterized
function Set-CipherSuites {
    param(
        [bool]$secureEnvironment
    )

    # secure and insecure lists defined inline
    $secureCipherSuites = "TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_NULL_SHA256,TLS_RSA_WITH_NULL_SHA,TLS_PSK_WITH_AES_256_GCM_SHA384,TLS_PSK_WITH_AES_128_GCM_SHA256,TLS_PSK_WITH_AES_256_CBC_SHA384,TLS_PSK_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_NULL_SHA384,TLS_PSK_WITH_NULL_SHA256"
    $insecureCipherSuites = "TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_NULL_SHA256,TLS_RSA_WITH_NULL_SHA,TLS_PSK_WITH_AES_256_GCM_SHA384,TLS_PSK_WITH_AES_128_GCM_SHA256,TLS_PSK_WITH_AES_256_CBC_SHA384,TLS_PSK_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_NULL_SHA384,TLS_PSK_WITH_NULL_SHA256,TLS_RSA_WITH_DES_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_RC4_128_MD5,TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,TLS_RSA_EXPORT_WITH_RC4_40_MD5,SSL_RSA_WITH_DES_CBC_SHA,SSL_RSA_WITH_3DES_EDE_CBC_SHA,SSL_RSA_WITH_RC4_128_SHA,SSL_RSA_WITH_RC4_128_MD5,SSL_RSA_WITH_IDEA_CBC_SHA,SSL_RSA_WITH_DES_CBC_MD5,SSL_RSA_WITH_3DES_EDE_CBC_MD5,SSL_DH_DSS_WITH_DES_CBC_SHA,SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA,SSL_DH_DSS_WITH_DES_CBC_MD5,SSL_DH_DSS_WITH_3DES_EDE_CBC_MD5,SSL_DH_RSA_WITH_DES_CBC_SHA,SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA,SSL_DH_RSA_WITH_DES_CBC_MD5,SSL_DH_RSA_WITH_3DES_EDE_CBC_MD5,SSL_DHE_DSS_WITH_DES_CBC_SHA,SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA,SSL_DHE_DSS_WITH_DES_CBC_MD5,SSL_DHE_DSS_WITH_3DES_EDE_CBC_MD5,SSL_DHE_RSA_WITH_DES_CBC_SHA,SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,SSL_DHE_RSA_WITH_DES_CBC_MD5,SSL_DHE_RSA_WITH_3DES_EDE_CBC_MD5,SSL_DH_anon_WITH_RC4_128_MD5,SSL_DH_anon_WITH_DES_CBC_SHA,SSL_DH_anon_WITH_3DES_EDE_CBC_SHA,SSL_FORTEZZA_DMS_WITH_NULL_SHA,SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA,SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA,SSL_RSA_FIPS_WITH_DES_CBC_SHA,SSL_RSA_WITH_CAMELLIA_128_CBC_SHA,SSL_RSA_WITH_CAMELLIA_256_CBC_SHA,TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,TLS_RSA_WITH_SEED_CBC_SHA,TLS_RSA_WITH_IDEA_CBC_SHA"
    
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    if ($secureEnvironment) {
        $selectedCipherSuites = $secureCipherSuites
        Write-Output "Configuring a secure environment..."
    } else {
        $selectedCipherSuites = $insecureCipherSuites
        Write-Output "Configuring an insecure environment..."
    }

    Set-ItemProperty -Path $regPath -Name "Functions" -Value $selectedCipherSuites
    Set-ItemProperty -Path $regPath -Name "Enabled" -Value 1

    # read back the value and display it for confirmation
    $actual = (Get-ItemProperty -Path $regPath -Name "Functions").Functions
    Write-Output "Cipher Suites have been updated to:"
    Write-Output $actual

    if ($actual -eq $selectedCipherSuites) {
        Write-Output "Verification successful: registry contains the expected list."
    } else {
        Write-Warning "Verification failed: registry value does not match selection."
    }

    Write-Output "Please restart the server to apply the changes."
}

# wireshark uninstaller logic
$wiresharkDisplayName = "Wireshark 2.2.1 (64-bit)"
$uninstallerPath = "$env:ProgramFiles\Wireshark\uninstall.exe"
$silentUninstallSwitch = "/S"

function Test-WiresharkInstalled {
    return Test-Path -Path $uninstallerPath
}

function Uninstall-Wireshark {
    if (Test-WiresharkInstalled) {
        Write-Output "Uninstalling Wireshark..."
        & $uninstallerPath $silentUninstallSwitch
        Write-Output "$($wiresharkDisplayName) has been uninstalled."
    } else {
        Write-Output "$($wiresharkDisplayName) is not installed."
    }
}

# admin/guest account toggle logic (secure = Off, insecure = On)
function Set-AdminGuestAccounts {
    param(
        [bool]$secureEnvironment
    )

    $toggle = if ($secureEnvironment) { "Off" } else { "On" }
    $administratorPasswordPlain = ""
    $guestPasswordPlain = ""

    function Add-ReportLine {
        param([ref]$Report, [string]$Text)
        $Report.Value += $Text
    }

    function Try-ReportStep {
        param([ref]$Report, [string]$Label, [scriptblock]$Action)

        try {
            & $Action
            Add-ReportLine -Report $Report -Text "[OK] $Label"
            return $true
        } catch {
            Add-ReportLine -Report $Report -Text "[FAIL] $Label - $($_.Exception.Message)"
            return $false
        }
    }

    function Get-AdministratorsGroupName {
        $group = Get-LocalGroup | Where-Object { $_.SID.Value -match '-544$' } | Select-Object -First 1
        if (-not $group) { throw "Could not find local Administrators group (SID ...-544)." }
        return $group.Name
    }

    function Test-IsBuiltInAdministrator {
        param([string]$Name)

        try {
            $user = Get-LocalUser -Name $Name -ErrorAction Stop
            return ($user.SID.Value -match '-500$')
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
            Add-ReportLine -Report $Report -Text "[INFO] $Name account did not exist."

            if ([string]::IsNullOrEmpty($PasswordPlain)) {
                Try-ReportStep -Report $Report -Label "Created $Name account with no password." -Action {
                    New-LocalUser -Name $Name -NoPassword -Description "$Name (created by script)" | Out-Null
                } | Out-Null
            } else {
                $securePassword = ConvertTo-SecureString $PasswordPlain -AsPlainText -Force
                Try-ReportStep -Report $Report -Label "Created $Name account (password set)." -Action {
                    New-LocalUser -Name $Name -Password $securePassword -Description "$Name (created by script)" | Out-Null
                } | Out-Null
            }

            $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
            if (-not $user) {
                Add-ReportLine -Report $Report -Text "[FAIL] $Name still not present after creation attempt."
                return
            }
        } else {
            Add-ReportLine -Report $Report -Text "[INFO] $Name account exists."
        }

        $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
        if ($user.Enabled) {
            Add-ReportLine -Report $Report -Text "[OK] $Name already enabled."
        } else {
            Try-ReportStep -Report $Report -Label "Enabled $Name (Enable-LocalUser)." -Action {
                Enable-LocalUser -Name $Name
            } | Out-Null

            $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
            if (-not $user.Enabled) {
                Try-ReportStep -Report $Report -Label "Enabled $Name (net user /active:yes fallback)." -Action {
                    cmd.exe /c "net user `"$Name`" /active:yes" | Out-Null
                } | Out-Null
            }

            $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
            if ($user.Enabled) {
                Add-ReportLine -Report $Report -Text "[OK] $Name enabled (verified)."
            } else {
                Add-ReportLine -Report $Report -Text "[FAIL] $Name still disabled after attempts (likely Local Security Policy/GPO)."
            }
        }

        if ([string]::IsNullOrEmpty($PasswordPlain)) {
            Try-ReportStep -Report $Report -Label "Set password to (none)." -Action {
                cmd.exe /c "net user `"$Name`" `"`"" | Out-Null
            } | Out-Null
        } else {
            $securePassword2 = ConvertTo-SecureString $PasswordPlain -AsPlainText -Force
            Try-ReportStep -Report $Report -Label "Set password to (password set)." -Action {
                Set-LocalUser -Name $Name -Password $securePassword2
            } | Out-Null
        }

        Try-ReportStep -Report $Report -Label "Add to '$AdminsGroupName' (Add-LocalGroupMember)." -Action {
            Add-LocalGroupMember -Group $AdminsGroupName -Member $Name -ErrorAction Stop
        } | Out-Null

        $isMember = $false
        try {
            $members = Get-LocalGroupMember -Group $AdminsGroupName -ErrorAction Stop
            $isMember = $members.Name -match "(^|\\)$([regex]::Escape($Name))$"
        } catch { }

        if (-not $isMember) {
            Try-ReportStep -Report $Report -Label "Add to '$AdminsGroupName' (net localgroup fallback)." -Action {
                cmd.exe /c "net localgroup `"$AdminsGroupName`" `"$Name`" /add" | Out-Null
            } | Out-Null
        }

        $isMember = $false
        try {
            $members = Get-LocalGroupMember -Group $AdminsGroupName -ErrorAction Stop
            $isMember = $members.Name -match "(^|\\)$([regex]::Escape($Name))$"
        } catch { }

        if ($isMember) {
            Add-ReportLine -Report $Report -Text "[OK] $Name is in '$AdminsGroupName' (verified)."
        } else {
            Add-ReportLine -Report $Report -Text "[FAIL] $Name is NOT in '$AdminsGroupName' after attempts."
        }
    }

    function Remove-UserByNameIfSafe {
        param(
            [string]$Name,
            [ref]$Report
        )

        $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
        if (-not $user) {
            Add-ReportLine -Report $Report -Text "[INFO] $Name does not exist (nothing to delete)."
            return
        }

        if (Test-IsBuiltInAdministrator -Name $Name) {
            Add-ReportLine -Report $Report -Text "[WARN] $Name is the built-in Administrator (RID 500). Skipping delete for safety/compatibility."
            return
        }

        Try-ReportStep -Report $Report -Label "Deleted local user '$Name'." -Action {
            Remove-LocalUser -Name $Name -ErrorAction Stop
        } | Out-Null
    }

    function Remove-From-Admins {
        param(
            [string]$Name,
            [string]$AdminsGroupName,
            [ref]$Report
        )

        Try-ReportStep -Report $Report -Label "Remove '$Name' from '$AdminsGroupName' (Remove-LocalGroupMember)." -Action {
            Remove-LocalGroupMember -Group $AdminsGroupName -Member $Name -ErrorAction Stop
        } | Out-Null

        Try-ReportStep -Report $Report -Label "Remove '$Name' from '$AdminsGroupName' (net localgroup fallback)." -Action {
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
            Add-ReportLine -Report $Report -Text "[INFO] $Name does not exist (nothing to disable)."
            return
        }

        if (-not $user.Enabled) {
            Add-ReportLine -Report $Report -Text "[OK] $Name already disabled."
            return
        }

        Try-ReportStep -Report $Report -Label "Disabled $Name (Disable-LocalUser)." -Action {
            Disable-LocalUser -Name $Name
        } | Out-Null

        $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
        if ($user.Enabled) {
            Try-ReportStep -Report $Report -Label "Disabled $Name (net user /active:no fallback)." -Action {
                cmd.exe /c "net user `"$Name`" /active:no" | Out-Null
            } | Out-Null
        }

        $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
        if (-not $user.Enabled) {
            Add-ReportLine -Report $Report -Text "[OK] $Name disabled (verified)."
        } else {
            Add-ReportLine -Report $Report -Text "[FAIL] $Name still enabled after attempts (likely Local Security Policy/GPO)."
        }
    }

    $limitBlank = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LimitBlankPasswordUse -ErrorAction SilentlyContinue).LimitBlankPasswordUse
    $policyNote = if ($null -eq $limitBlank) {
        "LimitBlankPasswordUse not found (policy may still exist elsewhere)."
    } else {
        "LimitBlankPasswordUse = $limitBlank (1 = blank passwords restricted)."
    }

    $adminsGroupName = Get-AdministratorsGroupName
    $adminReport = @()
    $guestReport = @()

    if ($toggle -eq "On") {
        Ensure-UserByName -Name "Administrator" -PasswordPlain $administratorPasswordPlain -AdminsGroupName $adminsGroupName -Report ([ref]$adminReport)
        Ensure-UserByName -Name "Guest" -PasswordPlain $guestPasswordPlain -AdminsGroupName $adminsGroupName -Report ([ref]$guestReport)
    } elseif ($toggle -eq "Off") {
        Remove-UserByNameIfSafe -Name "Administrator" -Report ([ref]$adminReport)
        Remove-From-Admins -Name "Guest" -AdminsGroupName $adminsGroupName -Report ([ref]$guestReport)
        Disable-UserByName -Name "Guest" -Report ([ref]$guestReport)
    } else {
        throw "Invalid toggle value: '$toggle'."
    }

    Write-Host "`n==================== ADMIN/GUEST SUMMARY ====================" -ForegroundColor Yellow
    Write-Host $policyNote -ForegroundColor DarkYellow
    Write-Host "Administrators group resolved as: '$adminsGroupName'" -ForegroundColor DarkYellow
    Write-Host "Toggle mode: $toggle (secure maps to Off, insecure maps to On)" -ForegroundColor DarkYellow

    Write-Host "`n--- Administrator ---" -ForegroundColor Cyan
    $adminReport | ForEach-Object { Write-Host $_ }

    Write-Host "`n--- Guest ---" -ForegroundColor Cyan
    $guestReport | ForEach-Object { Write-Host $_ }

    Write-Host "`n--- Verification: Users ---" -ForegroundColor Yellow
    Get-LocalUser -Name "Administrator","Guest" -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled, PasswordRequired, PasswordExpires, LastLogon, SID |
        Format-Table -AutoSize

    Write-Host "`n--- Verification: '$adminsGroupName' Members (filtered) ---" -ForegroundColor Yellow
    Get-LocalGroupMember -Group $adminsGroupName -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "(^|\\)Administrator$" -or $_.Name -match "(^|\\)Guest$" } |
        Format-Table -AutoSize
}

# utility prompting helpers
function Request-YesNo {
    param(
        [string]$Message
    )
    while ($true) {
        $response = Read-Host "$Message (Yes/No)"
        switch -regex ($response) {
            '^(?i)y(es)?$' { return $true }
            '^(?i)n(o)?$' { return $false }
            default { Write-Host 'Please answer Yes or No.' }
        }
    }
}

function Request-SecureChoice {
    param([string]$Name)
    while ($true) {
        $resp = Read-Host "Set $Name to secure or insecure? (secure/insecure)"
        switch -regex ($resp) {
            '^(?i)secure$' { return $true }
            '^(?i)insecure$' { return $false }
            default { Write-Host 'Please enter "secure" or "insecure".' }
        }
    }
}

# main execution

if (-not (Test-Admin)) {
    Write-Error "Access Denied. Please run with Administrator privileges."
    exit 1
}

$tasks = @(
    @{ Name='Protocol Toggle (TLS & CLS)'; Action={ $secure = Request-SecureChoice -Name 'protocols'; Set-ProtocolSecurity -secureEnvironment $secure } },
    @{ Name='Cipher Suites Toggle'; Action={ $secure = Request-SecureChoice -Name 'cipher suites'; Set-CipherSuites -secureEnvironment $secure } },
    @{ Name='Admin/Guest Account Toggle'; Action={ $secure = Request-SecureChoice -Name 'admin/guest accounts'; Set-AdminGuestAccounts -secureEnvironment $secure } },
    @{ Name='Wireshark Uninstall'; Action={ if (Request-YesNo 'Do you want to uninstall Wireshark?') { Uninstall-Wireshark } } }
)

foreach ($task in $tasks) {
    if (Request-YesNo "Would you like to run $($task.Name)?") {
        & $task.Action
    } else {
        Write-Host "Skipping $($task.Name)."
    }
}
