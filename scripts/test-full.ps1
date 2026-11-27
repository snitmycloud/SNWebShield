# The full backend suite, in parallel with pytest-xdist when it is installed (about 1 minute; about 5 minutes without it),
# then the frontend unit tests and the production build. Run from any folder. Before merging a phase, also run scripts\fresh-clone-check.ps1.
$root = Split-Path $PSScriptRoot -Parent
Push-Location (Join-Path $root "backend")
try {
  $python = ".\.venv\Scripts\python.exe"
  $parallel = (& $python -m pip list 2>$null | Select-String -Pattern "^pytest-xdist\s") -ne $null
  if ($parallel) { & $python -m pytest -q -p no:cacheprovider -n 6 } else { & $python -m pytest -q -p no:cacheprovider }
  $code = $LASTEXITCODE
} finally { Pop-Location }
if ($code -ne 0) { exit $code }
Push-Location (Join-Path $root "frontend")
try { npm test; if ($LASTEXITCODE -eq 0) { npm run build } } finally { Pop-Location }
