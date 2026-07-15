$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path $PSScriptRoot '..\\powershell\\rdp_public_ip_restriction.ps1'

if (-not (Test-Path -LiteralPath $scriptPath)) {
    throw "Expected RDP restriction script at $scriptPath."
}

. $scriptPath

if ((Test-PublicIPv4 -Address '8.8.8.8') -ne '8.8.8.8') {
    throw 'Expected a valid public IPv4 address to be returned unchanged.'
}

try {
    Test-PublicIPv4 -Address '10.0.0.8'
    throw 'Expected a private IPv4 address to be rejected.'
}
catch [System.Management.Automation.RuntimeException] {
    if ($_.Exception.Message -notmatch 'public IPv4') {
        throw
    }
}
