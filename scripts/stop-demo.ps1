<#
.SYNOPSIS
  Stops the demo processes started by start-demo.ps1 (API, scan worker, web app). Nothing else is touched.
#>
$targets = Get-CimInstance Win32_Process | Where-Object {
  ($_.Name -match "python|node|cmd") -and ($_.CommandLine -match 'uvicorn\s+app\.main:app|app\.cli\.operations\s+scan-worker|vite|npm run dev')
}
foreach ($p in $targets) {
  Write-Host ("Stopping {0} ({1})" -f $p.ProcessId, $p.Name)
  Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
}
if (-not $targets) { Write-Host "Nothing to stop." }
