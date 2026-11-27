# Starts the two local background roles (scan worker and monitor) in their own windows, skipping any that is already running.
# For everything at once, including the API and web app, and automatic restarts, use scripts\install-autostart.ps1 (the supervisor).
# Does not start the API or frontend, and never touches Azure.
$backend = Join-Path (Split-Path $PSScriptRoot -Parent) "backend"
$python = Join-Path $backend ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { Write-Error "Backend venv not found at $python"; exit 1 }
$running = @(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'app\.cli\.operations' } | ForEach-Object CommandLine)
foreach ($role in "scan-worker", "monitor") {
    if ($running | Where-Object { $_ -match "operations\s+$role(\s|$)" }) { Write-Host "$role already running"; continue }
    Start-Process -FilePath $python -ArgumentList "-m", "app.cli.operations", $role -WorkingDirectory $backend
    Write-Host "$role started"
}
