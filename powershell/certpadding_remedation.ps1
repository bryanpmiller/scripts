# CVE-2013-3900 mitigation (WinVerifyTrust padding check)
# Sets EnableCertPaddingCheck=1 in both 64-bit + 32-bit Wintrust config hives.

$paths = @(
  "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config",
  "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
)

foreach ($p in $paths) {
  if (-not (Test-Path $p)) {
    New-Item -Path $p -Force | Out-Null
  }

  New-ItemProperty -Path $p `
    -Name "EnableCertPaddingCheck" `
    -PropertyType DWord `
    -Value 1 `
    -Force | Out-Null
}

Write-Host "Applied: EnableCertPaddingCheck=1 (DWORD) in both registry paths."
Write-Host "Recommended: restart Windows to ensure all processes pick up the change."
