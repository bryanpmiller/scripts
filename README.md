# Public Script Repo

This folder contains small Bash and PowerShell utilities for Windows hardening, remediation, software cleanup, and lab-state toggling.

## Folder Layout

```text
scripts/
  bash/
    folder_check.sh
  powershell/
    admin_guest_account_toggle.ps1
    allow_inbound_ping.ps1
    certpadding_remedation.ps1
    cipher_suites_toggle.ps1
    download_windowsupdates.ps1
    manage_toggles.ps1
    openfirewall.ps1
    protocol_toggle.ps1
    teams_remove_tool.ps1
    updated_libcurl.ps1
    windows-update-toggle.ps1
    wireshark_remove_tool.ps1
```

## General Usage

### PowerShell

Run PowerShell as Administrator for scripts that touch `HKLM`, Windows services, firewall rules, local users, Appx packages, or installed software.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\scripts\powershell\<script-name>.ps1
```

Several scripts use variables near the top of the file, such as `$Mode`, `$Toggle`, or `$secureEnvironment`. Set those values before execution.

### Bash

Run Bash scripts from a Linux shell or compatible environment.

```bash
chmod +x scripts/bash/<script-name>.sh
./scripts/bash/<script-name>.sh
```

## Bash Scripts

| Script | Purpose | Notes |
| --- | --- | --- |
| `bash/folder_check.sh` | Contains a setup snippet for creating and running `ls_script.sh`, which monitors `/opt/nessus_agent/var/nessus/triggers` until the directory becomes empty. | The current file is wrapped like a copied block/comment and is best treated as a snippet. The generated script lists the trigger directory, waits 120 seconds between checks, and displays a progress bar while sleeping. |

## PowerShell Scripts

| Script | Purpose | Key behavior |
| --- | --- | --- |
| `powershell/admin_guest_account_toggle.ps1` | Toggles local `Administrator` and `Guest` account behavior for lab scenarios. | Uses `$Toggle = "On"` to enable/create the accounts, attempt blank or configured passwords, and add them to the local Administrators group. Uses `$Toggle = "Off"` to remove a non-built-in Administrator account, remove Guest from Administrators, and disable Guest. Requires Administrator privileges. Intended for lab use only. |
| `powershell/allow_inbound_ping.ps1` | Adds an inbound Windows Firewall rule for ICMPv4 echo requests from a specific remote public IP. | Replace `YOUR_PUBLIC_IP` before running. Useful when allowing ping to a VM from a known source address. Also ensure any cloud network security group allows ICMP traffic. |
| `powershell/certpadding_remedation.ps1` | Applies the CVE-2013-3900 WinVerifyTrust certificate padding mitigation. | Sets `EnableCertPaddingCheck=1` under both 64-bit and 32-bit Wintrust registry paths. A reboot is recommended after applying. Requires Administrator privileges. |
| `powershell/cipher_suites_toggle.ps1` | Configures Windows cipher suite ordering for a secure or intentionally insecure lab state. | Set `$secureEnvironment = $true` for the secure list or `$false` for the insecure list. Writes the selected cipher suite list to the SSL policy registry path and enables the policy. Reboot required. |
| `powershell/download_windowsupdates.ps1` | Installs the `PSWindowsUpdate` module if needed, lists available Windows updates, and installs all updates. | Temporarily bypasses execution policy for the current process, installs NuGet and `PSWindowsUpdate` if missing, then runs `Install-WindowsUpdate -AcceptAll -AutoReboot`. Requires internet access and Administrator privileges. |
| `powershell/manage_toggles.ps1` | Interactive manager that combines multiple lab toggles and cleanup actions. | Prompts the user to run protocol toggles, cipher suite toggles, Admin/Guest account toggles, and Wireshark removal. Secure mode hardens protocols/ciphers and turns Admin/Guest lab settings off; insecure mode enables weaker lab settings. Requires Administrator privileges. |
| `powershell/openfirewall.ps1` | Adds an inbound Windows Firewall rule named `Allow Tenable`. | Allows any protocol from remote address `10.0.0.8` on any profile. Adjust the remote address before running if your scanner or source host differs. |
| `powershell/protocol_toggle.ps1` | Toggles SSL/TLS protocol support for secure or intentionally insecure lab states. | Set `$secureEnvironment = $true` to disable SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1 while enabling TLS 1.2. Set it to `$false` to do the opposite for lab testing. Writes SCHANNEL registry keys and requires a reboot. |
| `powershell/rdp_public_ip_restriction.ps1` | Restricts inbound RDP access to one prompted public IPv4 address. | Validates the entered IPv4 address, disables enabled inbound TCP/3389 allow rules, and creates one replacement allow rule scoped to that address. Requires Administrator privileges. It does not enable RDP or change its listening port. |
| `powershell/teams_remove_tool.ps1` | Removes Microsoft Teams from Windows 11 systems and verifies cleanup. | Stops Teams processes, removes new Teams Appx/MSIX packages, removes provisioned packages, runs classic Teams uninstallers, deletes common leftover folders and shortcuts, then searches for remaining Teams executables. Requires Administrator privileges for full cleanup. |
| `powershell/updated_libcurl.ps1` | Upgrades curl and Git with `winget`, then prints the installed curl version. | Runs `winget upgrade curl` and `winget upgrade Git.Git`, then executes `curl.exe --version`. Requires `winget` and internet access. |
| `powershell/windows-update-toggle.ps1` | Enables or disables Windows Automatic Updates using policy and service settings. | Set `$Mode = "Off"` to set `NoAutoUpdate=1`, stop `wuauserv`, and disable the service. Set `$Mode = "On"` to remove the policy value, set the service to Manual, and start it. Includes verification output. Requires Administrator privileges. |
| `powershell/wireshark_remove_tool.ps1` | Silently uninstalls Wireshark 2.2.1 from the default install path. | Checks for `$env:ProgramFiles\Wireshark\uninstall.exe` and runs it with `/S`. If Wireshark is installed elsewhere or is a different version, update the path or logic before running. |

## Security Notes

- Scripts that enable insecure protocols, weak cipher suites, blank passwords, Guest access, or privileged lab accounts should only be used in isolated cyber range environments.
- Registry and service changes may be overridden by Group Policy, local security policy, MDM, or endpoint management tooling.
- Several changes require a reboot before Windows fully applies them.
- Firewall scripts contain hard-coded remote addresses. Confirm those addresses match your environment before execution.
- Software removal scripts can delete user-level application data and shortcuts. Review paths before running on shared systems.

## Quick Selection Guide

| Need | Use |
| --- | --- |
| Harden or weaken SSL/TLS protocol versions | `protocol_toggle.ps1` |
| Harden or weaken cipher suites | `cipher_suites_toggle.ps1` |
| Run several toggle tools interactively | `manage_toggles.ps1` |
| Toggle Windows Updates | `windows-update-toggle.ps1` |
| Install all Windows Updates | `download_windowsupdates.ps1` |
| Remove Microsoft Teams | `teams_remove_tool.ps1` |
| Remove Wireshark | `wireshark_remove_tool.ps1` or `manage_toggles.ps1` |
| Allow inbound ping from a known public IP | `allow_inbound_ping.ps1` |
| Restrict inbound RDP to one public IP | `rdp_public_ip_restriction.ps1` |
| Allow scanner traffic from a known internal IP | `openfirewall.ps1` |
| Apply WinVerifyTrust padding mitigation | `certpadding_remedation.ps1` |
| Upgrade curl and Git | `updated_libcurl.ps1` |
| Monitor Nessus Agent trigger directory | `folder_check.sh` |
