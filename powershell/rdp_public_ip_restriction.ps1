[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PublicIp
)

$ErrorActionPreference = 'Stop'
$ruleName = 'Allow RDP From Public IP'

function Test-PublicIPv4 {
    param(
        [Parameter(Mandatory)]
        [string]$Address
    )

    $ipAddress = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$ipAddress) -or
        $ipAddress.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "'$Address' is not a valid public IPv4 address."
    }

    $octets = $ipAddress.GetAddressBytes()
    $isNonPublic =
        $octets[0] -eq 0 -or
        $octets[0] -eq 10 -or
        $octets[0] -eq 127 -or
        ($octets[0] -eq 100 -and $octets[1] -ge 64 -and $octets[1] -le 127) -or
        ($octets[0] -eq 169 -and $octets[1] -eq 254) -or
        ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
        ($octets[0] -eq 192 -and $octets[1] -eq 168) -or
        $octets[0] -ge 224

    if ($isNonPublic) {
        throw "'$Address' is not a public IPv4 address."
    }

    return $ipAddress.ToString()
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell session.'
    }
}

function Disable-ExistingRdpAllowRules {
    $rdpFilters = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
        Get-NetFirewallPortFilter |
        Where-Object { $_.Protocol -eq 'TCP' -and $_.LocalPort -eq '3389' }

    foreach ($filter in $rdpFilters) {
        Get-NetFirewallRule -AssociatedNetFirewallPortFilter $filter |
            Disable-NetFirewallRule -WhatIf:$WhatIfPreference
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    if ([string]::IsNullOrWhiteSpace($PublicIp)) {
        $PublicIp = Read-Host 'Enter the public IPv4 address allowed to use RDP'
    }

    $PublicIp = Test-PublicIPv4 -Address $PublicIp.Trim()
    Test-Administrator

    Disable-ExistingRdpAllowRules
    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue -WhatIf:$WhatIfPreference
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 -RemoteAddress $PublicIp -Profile Any -WhatIf:$WhatIfPreference | Out-Null

    Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue |
        Get-NetFirewallAddressFilter |
        Select-Object Name, RemoteAddress
}
