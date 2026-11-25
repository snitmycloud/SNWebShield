# Starts the local background roles (scheduler, monitoring worker, notifications, legacy assessment worker,
# scan worker) in their own windows, skipping any role that is already running. Run from anywhere.
# Does not start the API or frontend, and never touches Azure.
$backend = Join-Path (Split-Path $PSScriptRoot -Parent) "backend"
$python = Join-Path $backend ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { Write-Error "Backend venv not found at $python"; exit 1 }
$running = @(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'app\.cli\.operations' } | ForEach-Object CommandLine)
foreach ($role in "scheduler", "worker", "notifications", "assessment-worker", "scan-worker") {
    if ($running | Where-Object { $_ -match "operations\s+$role(\s|$)" }) { Write-Host "$role already running"; continue }
    Start-Process -FilePath $python -ArgumentList "-m", "app.cli.operations", $role -WorkingDirectory $backend
    Write-Host "$role started"
}
