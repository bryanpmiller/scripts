<#
.SYNOPSIS
    Interactive manager for toggling security settings and uninstalling Wireshark.

.DESCRIPTION
    This script combines three existing helpers into a single interactive tool. 
        - Protocol Toggle: Enables or disables SSL/TLS protocols based on user choice.
        - Cipher Suites Toggle: Configures the system's cipher suites to a secure or insecure set based on user choice.
        - Wireshark Uninstaller: Offers the option to uninstall Wireshark if it is installed.
    
    For each of the toggle scripts (protocols and cipher suites) the user is prompted whether to run
    it and, if so, whether to configure the machine in a "secure" or "insecure" state.
    The Wireshark uninstaller can be run independently.

.NOTES
    Author        : Bryan Miller (based on original scripts by Josh Madakor)
    Date Created  : 2026-02-27
    Version       : 1.0

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
    @{ Name='Wireshark Uninstall'; Action={ if (Request-YesNo 'Do you want to uninstall Wireshark?') { Uninstall-Wireshark } } }
)

foreach ($task in $tasks) {
    if (Request-YesNo "Would you like to run $($task.Name)?") {
        & $task.Action
    } else {
        Write-Host "Skipping $($task.Name)."
    }
}
