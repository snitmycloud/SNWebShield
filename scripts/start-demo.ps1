<#
.SYNOPSIS
  Starts everything the demo needs, each in its own window, skipping what is already running:
  the API (port 8000), the scan worker, and the web app (port 5173).

.DESCRIPTION
  * Nuclei (the optional extra template checks) is ON by default in development and only runs while its self-test passes.
    It adds about 1.5 minutes to a scan. For a faster demo run   $env:NUCLEI_ENABLED = 'false'   before this script.
  * Nothing is deployed anywhere; everything runs on this computer.
  * Run from any folder:  powershell -ExecutionPolicy Bypass -File scripts\start-demo.ps1
  * To stop everything: close the three windows (or run  scripts\stop-demo.ps1).
#>
$root = Split-Path $PSScriptRoot -Parent
$backend = Join-Path $root "backend"
$frontend = Join-Path $root "frontend"
$python = Join-Path $backend ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { Write-Error "Backend virtual environment not found at $python"; exit 1 }

$procs = @(Get-CimInstance Win32_Process | ForEach-Object CommandLine)
function Test-Running($pattern) { [bool]($procs | Where-Object { $_ -match $pattern }) }

if (Test-Running 'uvicorn\s+app\.main:app') { Write-Host "API already running" }
else {
  Start-Process -FilePath $python -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000" -WorkingDirectory $backend
  Write-Host "API starting on http://127.0.0.1:8000"
}
if (Test-Running 'app\.cli\.operations\s+scan-worker') { Write-Host "scan worker already running" }
else {
  Start-Process -FilePath $python -ArgumentList "-m", "app.cli.operations", "scan-worker" -WorkingDirectory $backend
  Write-Host "scan worker starting"
}
if (Test-Running 'app\.cli\.operations\s+monitor') { Write-Host "monitor already running" }
else {
  Start-Process -FilePath $python -ArgumentList "-m", "app.cli.operations", "monitor" -WorkingDirectory $backend
  Write-Host "monitor starting (scheduled scans, uptime checks, alerts)"
}
if (Test-Running 'vite') { Write-Host "web app already running" }
else {
  Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "npm run dev" -WorkingDirectory $frontend
  Write-Host "web app starting on http://127.0.0.1:5173"
}

Start-Sleep -Seconds 8
foreach ($check in @(@("API", "http://127.0.0.1:8000/api/v1/health"), @("Web app", "http://127.0.0.1:5173"))) {
  try { $code = (Invoke-WebRequest $check[1] -UseBasicParsing -TimeoutSec 10).StatusCode; Write-Host ("{0,-8} OK ({1})" -f $check[0], $code) }
  catch { Write-Host ("{0,-8} NOT READY yet - wait a few seconds and run this script again" -f $check[0]) }
}
Write-Host ""
Write-Host "Open http://127.0.0.1:5173 and sign in with the demo account (see docs\DEMO_SCRIPT.md)."
