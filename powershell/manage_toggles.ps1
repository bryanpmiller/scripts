<#
.SYNOPSIS
    Interactive manager for toggling security settings and uninstalling Wireshark.

.DESCRIPTION
    This script combines three existing helpers into a single interactive tool.  For each
    of the toggle scripts (protocols and cipher suites) the user is prompted whether to run
    it and, if so, whether to configure the machine in a "secure" or "insecure" state.
    The Wireshark uninstaller can be run independently.

.NOTES
    Author        : Bryan Miller (based on original scripts by Josh Madakor)
    Date Created  : 2026-02-27
    Version       : 1.0

#>

# -- helper functions imported from the original scripts ------------------------------------------------

function Check-Admin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# protocol toggle logic extracted from protocol_toggle.ps1, parameterized
function Set-ProtocolSecurity {
    param(
        [bool]$secureEnvironment
    )

    # SSL 2.0 paths
    $serverPathSSL2 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
    $clientPathSSL2 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"

    if ($secureEnvironment) {
        New-Item -Path $serverPathSSL2 -Force | Out-Null
        New-ItemProperty -Path $serverPathSSL2 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $serverPathSSL2 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        New-Item -Path $clientPathSSL2 -Force | Out-Null
        New-ItemProperty -Path $clientPathSSL2 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $clientPathSSL2 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        Write-Host "SSL 2.0 has been disabled."
    } else {
        New-Item -Path $serverPathSSL2 -Force | Out-Null
        New-ItemProperty -Path $serverPathSSL2 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $serverPathSSL2 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        New-Item -Path $clientPathSSL2 -Force | Out-Null
        New-ItemProperty -Path $clientPathSSL2 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $clientPathSSL2 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        Write-Host "SSL 2.0 has been enabled."
    }

    # SSL 3.0
    $serverPathSSL3 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
    $clientPathSSL3 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"

    if ($secureEnvironment) {
        New-Item -Path $serverPathSSL3 -Force | Out-Null
        New-ItemProperty -Path $serverPathSSL3 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $serverPathSSL3 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        New-Item -Path $clientPathSSL3 -Force | Out-Null
        New-ItemProperty -Path $clientPathSSL3 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $clientPathSSL3 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        Write-Host "SSL 3.0 has been disabled."
    } else {
        New-Item -Path $serverPathSSL3 -Force | Out-Null
        New-ItemProperty -Path $serverPathSSL3 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $serverPathSSL3 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        New-Item -Path $clientPathSSL3 -Force | Out-Null
        New-ItemProperty -Path $clientPathSSL3 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $clientPathSSL3 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        Write-Host "SSL 3.0 has been enabled."
    }

    # TLS 1.0
    $serverPathTLS10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
    $clientPathTLS10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"

    if ($secureEnvironment) {
        New-Item -Path $serverPathTLS10 -Force | Out-Null
        New-ItemProperty -Path $serverPathTLS10 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $serverPathTLS10 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        New-Item -Path $clientPathTLS10 -Force | Out-Null
        New-ItemProperty -Path $clientPathTLS10 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $clientPathTLS10 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        Write-Host "TLS 1.0 has been disabled."
    } else {
        New-Item -Path $serverPathTLS10 -Force | Out-Null
        New-ItemProperty -Path $serverPathTLS10 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $serverPathTLS10 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        New-Item -Path $clientPathTLS10 -Force | Out-Null
        New-ItemProperty -Path $clientPathTLS10 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $clientPathTLS10 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        Write-Host "TLS 1.0 has been enabled."
    }

    # TLS 1.1
    $serverPathTLS11 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
    $clientPathTLS11 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"

    if ($secureEnvironment) {
        New-Item -Path $serverPathTLS11 -Force | Out-Null
        New-ItemProperty -Path $serverPathTLS11 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $serverPathTLS11 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        New-Item -Path $clientPathTLS11 -Force | Out-Null
        New-ItemProperty -Path $clientPathTLS11 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $clientPathTLS11 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        Write-Host "TLS 1.1 has been disabled."
    } else {
        New-Item -Path $serverPathTLS11 -Force | Out-Null
        New-ItemProperty -Path $serverPathTLS11 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $serverPathTLS11 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        New-Item -Path $clientPathTLS11 -Force | Out-Null
        New-ItemProperty -Path $clientPathTLS11 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $clientPathTLS11 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        Write-Host "TLS 1.1 has been enabled."
    }

    # TLS 1.2
    $serverPathTLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
    $clientPathTLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"

    if ($secureEnvironment) {
        New-Item -Path $serverPathTLS12 -Force | Out-Null
        New-ItemProperty -Path $serverPathTLS12 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $serverPathTLS12 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        New-Item -Path $clientPathTLS12 -Force | Out-Null
        New-ItemProperty -Path $clientPathTLS12 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $clientPathTLS12 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        Write-Host "TLS 1.2 has been enabled."
    } else {
        New-Item -Path $serverPathTLS12 -Force | Out-Null
        New-ItemProperty -Path $serverPathTLS12 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $serverPathTLS12 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        New-Item -Path $clientPathTLS12 -Force | Out-Null
        New-ItemProperty -Path $clientPathTLS12 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $clientPathTLS12 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
        Write-Host "TLS 1.2 has been disabled."
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
    $insecureCipherSuites = "TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_NULL_SHA256,TLS_RSA_WITH_NULL_SHA,TLS_PSK_WITH_AES_256_GCM_SHA384,TLS_PSK_WITH_AES_128_GCM_SHA256,TLS_PSK_WITH_AES_256_CBC_SHA384,TLS_PSK_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_NULL_SHA384,TLS_PSK_WITH_NULL_SHA256,TLS_RSA_WITH_DES_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_RC4_128_MD5,TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,TLS_RSA_EXPORT_WITH_RC4_40_MD5,SSL_RSA_WITH_DES_... (truncated for brevity)
    
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

    Write-Output "Cipher Suites have been updated to:" 
    Get-ItemProperty -Path $regPath -Name "Functions" | Select-Object -ExpandProperty Functions
    Write-Output "Please restart the server to apply the changes."
}

# wireshark uninstaller logic
$wiresharkDisplayName = "Wireshark 2.2.1 (64-bit)"
$uninstallerPath = "$env:ProgramFiles\Wireshark\uninstall.exe"
$silentUninstallSwitch = "/S"

function Is-WiresharkInstalled {
    return Test-Path -Path $uninstallerPath
}

function Uninstall-Wireshark {
    if (Is-WiresharkInstalled) {
        Write-Output "Uninstalling Wireshark..."
        & $uninstallerPath $silentUninstallSwitch
        Write-Output "$($wiresharkDisplayName) has been uninstalled."
    } else {
        Write-Output "$($wiresharkDisplayName) is not installed."
    }
}

# utility prompting helpers
function Prompt-YesNo {
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

function Prompt-SecureChoice {
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

if (-not (Check-Admin)) {
    Write-Error "Access Denied. Please run with Administrator privileges."
    exit 1
}

$tasks = @(
    @{ Name='Protocol Toggle'; Action={ $secure = Prompt-SecureChoice -Name 'protocols'; Set-ProtocolSecurity -secureEnvironment $secure } },
    @{ Name='Cipher Suites Toggle'; Action={ $secure = Prompt-SecureChoice -Name 'cipher suites'; Set-CipherSuites -secureEnvironment $secure } },
    @{ Name='Wireshark Uninstall'; Action={ if (Prompt-YesNo 'Do you want to uninstall Wireshark?') { Uninstall-Wireshark } } }
)

foreach ($task in $tasks) {
    if (Prompt-YesNo "Would you like to run $($task.Name)?") {
        & $task.Action
    } else {
        Write-Host "Skipping $($task.Name)."
    }
}
