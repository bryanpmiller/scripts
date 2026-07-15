<#
.SYNOPSIS
    Restricts inbound RDP access on TCP port 3389 to one public IPv4 address.
    Please test thoroughly in a non-production environment before deploying widely.
    Make sure to run as Administrator or with appropriate privileges.

.NOTES
    Author        : Bryan Miller
    Date Created  : 2026-07-14
    Last Modified : 2026-07-14
    Version       : 1.0

.TESTED ON
    Date(s) Tested  : 2026-07-14
    Tested By       : Automated PowerShell validation
    Systems Tested  : No live Windows firewall changes tested
    PowerShell Ver. : 5.1.26100.8655

.EDITED BY
    Date(s) Edited : 2026-07-14
    Edited By      : Bryan Miller
    Changes Made   : Added a comment-based help header for the RDP public-IP restriction script.
    Tested         : Yes; syntax and address-validation tests passed. Live firewall changes were not performed.

.USAGE
    Run the script from an elevated PowerShell session. It prompts for the one public IPv4 address to allow.
    Example syntax:
    PS C:\\> .\\rdp_public_ip_restriction.ps1

#>
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
