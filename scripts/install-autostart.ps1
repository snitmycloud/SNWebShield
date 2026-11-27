<#
.SYNOPSIS
  Makes SNWebShield start by itself when this computer boots, even when nobody is logged in, and keeps it running.
  RUN THIS YOURSELF AS ADMINISTRATOR (right-click PowerShell -> Run as administrator). Undo: scripts\uninstall-autostart.ps1

.DESCRIPTION
  Registers ONE Windows Task Scheduler task, "SNWebShield-Supervisor":
    * runs  backend\.venv\Scripts\python.exe -m app.cli.supervisor  at system start-up (whether or not you are logged in)
    * the supervisor starts the API (port 8000), the web app (port 5173, from the built frontend\dist), the scan worker and the
      monitor (scheduled scans, uptime checks, alerts), and restarts any of them that stops (back-off 1, 2, 4 ... 60 seconds)
    * Task Scheduler restarts the supervisor itself if it ever stops (every minute, up to 999 times); it has no time limit
    * runs under YOUR Windows account (so it can use the project, the private folders and your email outbox), not as SYSTEM
  No new package is installed. Nothing is deployed anywhere. Logs: %USERPROFILE%\SNWebShield-Private\logs.

  Windows needs your account password to run a task when you are not logged in. This script asks for it with the normal Windows
  password box and passes it only to Task Scheduler; it is never written to a file, a log or this repository.

  Do not run it while start-demo.ps1 processes are running (the supervisor then reports API/web as "external" and leaves them alone).
#>
#requires -RunAsAdministrator
param([string]$TaskName = "SNWebShield-Supervisor", [switch]$NoStartNow)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$backend = Join-Path $root "backend"
$frontend = Join-Path $root "frontend"
$python = Join-Path $backend ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { throw "Backend virtual environment not found at $python" }

if (-not (Test-Path (Join-Path $frontend "dist\index.html"))) {
  Write-Host "Building the web app (frontend\dist) ..."
  Push-Location $frontend
  try { cmd /c "npm run build"; if ($LASTEXITCODE -ne 0) { throw "npm run build failed" } } finally { Pop-Location }
}

$user = "$env:USERDOMAIN\$env:USERNAME"
$cred = Get-Credential -UserName $user -Message "Your Windows password, so the task can run at boot even when you are not logged in. It is given only to Task Scheduler."
if (-not $cred) { throw "Cancelled." }

$action = New-ScheduledTaskAction -Execute $python -Argument "-m app.cli.supervisor" -WorkingDirectory $backend
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
  -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
  -User $cred.UserName -Password $cred.GetNetworkCredential().Password -RunLevel Limited -Force `
  -Description "Starts SNWebShield (API, web app, scan worker, monitor) at boot and keeps it running." | Out-Null
Write-Host "Task '$TaskName' registered: runs at boot, restarts if it stops."

if (-not $NoStartNow) {
  Write-Host "Starting it now. If start-demo.ps1 processes are running, close them first (scripts\stop-demo.ps1)."
  Start-ScheduledTask -TaskName $TaskName
  Start-Sleep -Seconds 12
  Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo | Select-Object LastRunTime, LastTaskResult | Format-List
}
Write-Host "Check it: sign in as the administrator and open Admin > Workers. After a reboot, wait about 2 minutes."
