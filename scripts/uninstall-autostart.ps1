<#
.SYNOPSIS
  Removes the "SNWebShield-Supervisor" start-at-boot task (run as administrator). Stops the supervisor and the roles it started.
  Your data, the code and the database are not touched.
#>
#requires -RunAsAdministrator
param([string]$TaskName = "SNWebShield-Supervisor")
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $task) { Write-Host "No task named '$TaskName'."; exit 0 }
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
Write-Host "Task '$TaskName' removed. If any process is still running, scripts\stop-demo.ps1 stops it."
