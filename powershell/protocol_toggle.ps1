<#
.SYNOPSIS
    Toggles cryptographic protocols (secure vs insecure) on the system.
    Please test thoroughly in a non-production environment before deploying widely.
    Make sure to run as Administrator or with appropriate privileges.

.NOTES
    Author        : Josh Madakor
    Date Created  : 2024-09-09
    Last Modified : 2024-09-09
    Version       : 1.0

.TESTED ON
    Date(s) Tested  : 2024-09-09
    Tested By       : Josh Madakor
    Systems Tested  : Windows Server 2019 Datacenter, Build 1809
    PowerShell Ver. : 5.1.17763.6189

.EDITED BY
    Date(s) Edited : 2026-02-27
    Edited By      : Bryan Miller
    Changes Made   : modifed envionment variable to toggle between secure and insecure settings
    Tested         : No

.USAGE
    Set [$secureEnvironment = $true] to secure the system
    Example syntax:
    PS C:\> .\[filename].ps1 
#>
 
# Variable to determine if we want to make the computer secure or insecure
$secureEnvironment = $true

# Check if the script is run as Administrator
function Test-Admin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# generic helper to write and verify a dword registry value
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

# reusable protocol configuration logic
function Set-ProtocolSecurity {
    param(
        [bool]$secureEnvironment
    )

    function Set-ProtocolValue {
        param($Path,$Name,$Value)
        return Set-RegistryDword -Path $Path -Name $Name -Value $Value
    }

    function Set-Protocol {
        param(
            [string]$ServerPath,
            [string]$ClientPath,
            [int]$EnabledValue,
            [int]$DisabledByDefaultValue
        )
        $s1 = Set-ProtocolValue -Path $ServerPath -Name 'Enabled' -Value $EnabledValue
        $s2 = Set-ProtocolValue -Path $ServerPath -Name 'DisabledByDefault' -Value $DisabledByDefaultValue
        $s3 = Set-ProtocolValue -Path $ClientPath -Name 'Enabled' -Value $EnabledValue
        $s4 = Set-ProtocolValue -Path $ClientPath -Name 'DisabledByDefault' -Value $DisabledByDefaultValue
        return ($s1 -and $s2 -and $s3 -and $s4)
    }

    # SSL 2.0
    $serverPathSSL2 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
    $clientPathSSL2 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"
    if ($secureEnvironment) {
        if (Set-Protocol -ServerPath $serverPathSSL2 -ClientPath $clientPathSSL2 -EnabledValue 0 -DisabledByDefaultValue 1) {
            Write-Host "SSL 2.0 has been disabled."
        } else {
            Write-Warning "Failed to disable SSL 2.0; registry values may not match expected."
        }
    } else {
        if (Set-Protocol -ServerPath $serverPathSSL2 -ClientPath $clientPathSSL2 -EnabledValue 1 -DisabledByDefaultValue 0) {
            Write-Host "SSL 2.0 has been enabled."
        } else {
            Write-Warning "Failed to enable SSL 2.0; registry values may not match expected."
        }
    }

    # SSL 3.0
    $serverPathSSL3 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
    $clientPathSSL3 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"
    if ($secureEnvironment) {
        if (Set-Protocol -ServerPath $serverPathSSL3 -ClientPath $clientPathSSL3 -EnabledValue 0 -DisabledByDefaultValue 1) {
            Write-Host "SSL 3.0 has been disabled."
        } else {
            Write-Warning "Failed to disable SSL 3.0; registry values may not match expected."
        }
    } else {
        if (Set-Protocol -ServerPath $serverPathSSL3 -ClientPath $clientPathSSL3 -EnabledValue 1 -DisabledByDefaultValue 0) {
            Write-Host "SSL 3.0 has been enabled."
        } else {
            Write-Warning "Failed to enable SSL 3.0; registry values may not match expected."
        }
    }

    # TLS 1.0
    $serverPathTLS10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
    $clientPathTLS10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"
    if ($secureEnvironment) {
        if (Set-Protocol -ServerPath $serverPathTLS10 -ClientPath $clientPathTLS10 -EnabledValue 0 -DisabledByDefaultValue 1) {
            Write-Host "TLS 1.0 has been disabled."
        } else {
            Write-Warning "Failed to disable TLS 1.0; registry values may not match expected."
        }
    } else {
        if (Set-Protocol -ServerPath $serverPathTLS10 -ClientPath $clientPathTLS10 -EnabledValue 1 -DisabledByDefaultValue 0) {
            Write-Host "TLS 1.0 has been enabled."
        } else {
            Write-Warning "Failed to enable TLS 1.0; registry values may not match expected."
        }
    }

    # TLS 1.1
    $serverPathTLS11 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
    $clientPathTLS11 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"
    if ($secureEnvironment) {
        if (Set-Protocol -ServerPath $serverPathTLS11 -ClientPath $clientPathTLS11 -EnabledValue 0 -DisabledByDefaultValue 1) {
            Write-Host "TLS 1.1 has been disabled."
        } else {
            Write-Warning "Failed to disable TLS 1.1; registry values may not match expected."
        }
    } else {
        if (Set-Protocol -ServerPath $serverPathTLS11 -ClientPath $clientPathTLS11 -EnabledValue 1 -DisabledByDefaultValue 0) {
            Write-Host "TLS 1.1 has been enabled."
        } else {
            Write-Warning "Failed to enable TLS 1.1; registry values may not match expected."
        }
    }

    # TLS 1.2
    $serverPathTLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
    $clientPathTLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
    if ($secureEnvironment) {
        if (Set-Protocol -ServerPath $serverPathTLS12 -ClientPath $clientPathTLS12 -EnabledValue 1 -DisabledByDefaultValue 0) {
            Write-Host "TLS 1.2 has been enabled."
        } else {
            Write-Warning "Failed to enable TLS 1.2; registry values may not match expected."
        }
    } else {
        if (Set-Protocol -ServerPath $serverPathTLS12 -ClientPath $clientPathTLS12 -EnabledValue 0 -DisabledByDefaultValue 1) {
            Write-Host "TLS 1.2 has been disabled."
        } else {
            Write-Warning "Failed to disable TLS 1.2; registry values may not match expected."
        }
    }
    Write-Host "Please reboot for settings to take effect."
}

# Main script
if (-not (Test-Admin)) {
    Write-Error "Access Denied. Please run with Administrator privileges."
    exit 1
}

# apply the configuration based on the flag
Set-ProtocolSecurity -secureEnvironment $secureEnvironment

# SSL 2.0 settings
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

# SSL 3.0 settings
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

# TLS 1.0 settings
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

# TLS 1.1 settings
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

# TLS 1.2 settings
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
