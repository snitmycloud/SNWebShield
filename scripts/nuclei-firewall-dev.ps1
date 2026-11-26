<#
.SYNOPSIS
  DEVELOPMENT ONLY (Windows): blocks the pinned nuclei.exe from making ANY direct outbound network connection.

.DESCRIPTION
  SNWebShield forces all Nuclei traffic through its local egress proxy (127.0.0.1), which only ever contacts the scan's
  one verified host at its one pinned IP. This rule is the second, independent layer: even if Nuclei (or a template)
  ignored the proxy setting, Windows would refuse its connections. The Nuclei self-test reads this rule and keeps the engine
  OFF unless it exists, is enabled, blocks outbound, and names exactly the installed nuclei.exe.

  What it does:   creates ONE Windows Firewall rule named "SNWebShield-Nuclei-dev-block":
                    Direction Outbound, Action Block, Program = nuclei.exe, all profiles, any remote address.
  What it does NOT do:  it does not touch any other rule or program, does not change firewall settings, and does not
                    open anything. Traffic to this computer's own loopback address (the proxy) is not filtered by
                    Windows Firewall rules; the self-test verifies the proxy path still works after the rule exists.
  Undo:           scripts\nuclei-firewall-dev-undo.ps1

  Run this yourself from an ELEVATED (administrator) PowerShell. Preview first with -WhatIf.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\nuclei-firewall-dev.ps1 -WhatIf
  powershell -ExecutionPolicy Bypass -File scripts\nuclei-firewall-dev.ps1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  # Where install_nuclei.py put the binary. Change only if you installed it elsewhere (NUCLEI_DIR).
  [string]$ProgramPath = (Join-Path $env:USERPROFILE "SNWebShield-Private\engines\nuclei-3.11.1\nuclei.exe")
)

$ErrorActionPreference = "Stop"
$RuleName = "SNWebShield-Nuclei-dev-block"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "Run this from an elevated (Administrator) PowerShell."
  exit 1
}
if (-not (Test-Path -LiteralPath $ProgramPath -PathType Leaf)) {
  Write-Error "nuclei.exe was not found at: $ProgramPath  (run backend\tools\install_nuclei.py first, or pass -ProgramPath)"
  exit 1
}
$ProgramPath = (Resolve-Path -LiteralPath $ProgramPath).Path

$existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
if ($existing) {
  Write-Host "The rule '$RuleName' already exists:"
  $existing | Get-NetFirewallApplicationFilter | Format-List Program
  Write-Host "Nothing changed. Run nuclei-firewall-dev-undo.ps1 first if you want to recreate it."
  exit 0
}

if ($PSCmdlet.ShouldProcess($ProgramPath, "Create outbound BLOCK rule '$RuleName'")) {
  New-NetFirewallRule -DisplayName $RuleName `
    -Description "SNWebShield development: blocks the pinned nuclei.exe from direct network access. Its traffic must go through the local egress proxy. Remove with scripts\nuclei-firewall-dev-undo.ps1" `
    -Direction Outbound -Action Block -Program $ProgramPath -Profile Any -Enabled True | Out-Null
  Write-Host "Created rule '$RuleName' for $ProgramPath"
  Get-NetFirewallRule -DisplayName $RuleName | Format-List DisplayName, Enabled, Direction, Action, Profile
  Write-Host "Next: from backend\, run  .\.venv\Scripts\python.exe -m app.services.nuclei_selftest  (the firewall check should now pass)."
}
