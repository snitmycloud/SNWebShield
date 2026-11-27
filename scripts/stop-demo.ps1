<#
.SYNOPSIS
  Stops the demo processes started by start-demo.ps1 (API, scan worker, web app). Nothing else is touched.
#>
$task = Get-ScheduledTask -TaskName "SNWebShield-Supervisor" -ErrorAction SilentlyContinue
if ($task -and $task.State -eq "Running" -and -not $args.Contains("-Force")) {
  Write-Host "The auto-start supervisor is running and keeps everything alive. To stop it: Stop-ScheduledTask -TaskName SNWebShield-Supervisor  (or pass -Force to kill the processes anyway; the supervisor will start them again)."
  exit 0
}
$targets = Get-CimInstance Win32_Process | Where-Object {
  ($_.Name -match "python|node|cmd") -and ($_.CommandLine -match 'uvicorn\s+app\.main:app|app\.cli\.operations\s+(scan-worker|monitor)|vite|npm run dev')
}
foreach ($p in $targets) {
  Write-Host ("Stopping {0} ({1})" -f $p.ProcessId, $p.Name)
  Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
}
if (-not $targets) { Write-Host "Nothing to stop." }
