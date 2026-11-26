<#
.SYNOPSIS
  Removes the development firewall rule created by nuclei-firewall-dev.ps1.

.DESCRIPTION
  Deletes ONLY the rule named "SNWebShield-Nuclei-dev-block". No other rule is touched. After this, the Nuclei self-test's
  firewall check fails and the Nuclei engine stays OFF (the other scan checks are unaffected).

  Run this yourself from an ELEVATED (administrator) PowerShell. Preview first with -WhatIf.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\nuclei-firewall-dev-undo.ps1 -WhatIf
  powershell -ExecutionPolicy Bypass -File scripts\nuclei-firewall-dev-undo.ps1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param()

$ErrorActionPreference = "Stop"
$RuleName = "SNWebShield-Nuclei-dev-block"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "Run this from an elevated (Administrator) PowerShell."
  exit 1
}

$existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
if (-not $existing) {
  Write-Host "The rule '$RuleName' does not exist. Nothing to remove."
  exit 0
}
if ($PSCmdlet.ShouldProcess($RuleName, "Remove firewall rule")) {
  Remove-NetFirewallRule -DisplayName $RuleName
  Write-Host "Removed rule '$RuleName'. The Nuclei engine will now stay off (its self-test fails)."
}
