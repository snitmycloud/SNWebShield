# Quick backend tests: everything except the slow ones (about 1 minute). Use while you work.
# Then the frontend unit tests (seconds). Run from any folder.
$root = Split-Path $PSScriptRoot -Parent
Push-Location (Join-Path $root "backend")
try { & .\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider -m "not slow"; $code = $LASTEXITCODE } finally { Pop-Location }
if ($code -ne 0) { exit $code }
Push-Location (Join-Path $root "frontend")
try { npm test } finally { Pop-Location }
