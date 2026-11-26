<#
.SYNOPSIS
  Release check: clone the repository into a temporary folder, install it from scratch and prove that nothing needed is
  missing because of .gitignore (or because a file was never committed).

.DESCRIPTION
  What it checks, in order:
    1. The working copy has no uncommitted changes (a clone only contains what is COMMITTED).
    2. No file under the source folders is ignored by .gitignore while present on disk (this is how four vendored Nuclei
       templates in a folder called "backups" were once left out of the repository).
    3. A fresh `git clone` of the branch into a new temporary folder.
    4. A brand-new Python virtual environment and `pip install -r backend\requirements.txt`.
    5. The Nuclei manifest check on the clone: all vendored templates present, every SHA-256 equal to MANIFEST.json, the lock
       file pins both platforms, and every template is tracked by git.
    6. The backend tests (the full suite, or a quick subset with -Fast).
    7. The frontend: `npm ci`, `npm test`, `npm run build` (skip with -SkipFrontend).
  Exit code 0 only if everything passed. The temporary folder is deleted at the end (keep it with -Keep).

  Run it before every release:
      powershell -ExecutionPolicy Bypass -File scripts\fresh-clone-check.ps1
      powershell -ExecutionPolicy Bypass -File scripts\fresh-clone-check.ps1 -Fast -SkipFrontend     # a few minutes

.PARAMETER Branch   Branch to clone (default: the branch checked out now).
.PARAMETER Source   Repository to clone (default: this working copy). Use https://github.com/snitmycloud/SNWebShield.git to test what is on GitHub.
.PARAMETER Fast     Run a quick subset of the backend tests instead of the full suite.
.PARAMETER SkipFrontend  Do not install or test the frontend.
.PARAMETER AllowDirty    Continue even if there are uncommitted changes (they are NOT in the clone).
.PARAMETER Keep     Keep the temporary folder.
#>
param(
  [string]$Branch = "",
  [string]$Source = "",
  [switch]$Fast,
  [switch]$SkipFrontend,
  [switch]$AllowDirty,
  [switch]$Keep
)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
if (-not $Source) { $Source = $root }
if (-not $Branch) { $Branch = (git -C $root rev-parse --abbrev-ref HEAD).Trim() }
$results = [ordered]@{}
function Step($name, [scriptblock]$body) {
  Write-Host ""
  Write-Host "=== $name ===" -ForegroundColor Cyan
  $started = Get-Date
  try {
    & $body
    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) { throw "exit code $LASTEXITCODE" }
    $results[$name] = "PASS ({0:N0} s)" -f ((Get-Date) - $started).TotalSeconds
  } catch {
    $results[$name] = "FAIL: $($_.Exception.Message)"
    Write-Host $results[$name] -ForegroundColor Red
    $script:failed = $true
  }
  $global:LASTEXITCODE = 0
}
$failed = $false
$temp = Join-Path ([IO.Path]::GetTempPath()) ("snwebshield-fresh-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))

Step "1. No uncommitted changes" {
  $dirty = git -C $root status --porcelain
  if ($dirty -and -not $AllowDirty) { Write-Host $dirty; throw "uncommitted changes (commit them, or use -AllowDirty; the clone will not contain them)" }
}

Step "2. Nothing needed is hidden by .gitignore" {
  $ignored = git -C $root ls-files --others --ignored --exclude-standard
  $watch = '^(backend/(app|tests|migrations|tools)/|frontend/(src|tests)/|scripts/|docs/|CLAUDE\.md|README\.md)'
  $hidden = @($ignored | Where-Object { $_ -match $watch -and $_ -notmatch '__pycache__|\.pyc$|\.db$|node_modules|/dist/|\.pytest_cache|\.log$' })
  if ($hidden.Count) {
    Write-Host "Present on disk but ignored by .gitignore (they will be MISSING from a clone):"
    $hidden | Select-Object -First 25 | ForEach-Object { Write-Host "  $_" }
    throw "$($hidden.Count) ignored file(s) inside source folders"
  }
}

Step "3. Fresh clone of '$Branch'" {
  git clone --quiet --branch $Branch --single-branch $Source $temp
  if ($LASTEXITCODE -ne 0) { throw "git clone failed" }
  Write-Host "Cloned to $temp at $(git -C $temp rev-parse --short HEAD)"
}

$python = Join-Path $temp "backend\.venv\Scripts\python.exe"
Step "4. New virtual environment and pip install" {
  python -m venv (Join-Path $temp "backend\.venv")
  & $python -m pip install --quiet --disable-pip-version-check -r (Join-Path $temp "backend\requirements.txt")
}

Step "5. Nuclei manifest check on the clone" {
  $check = @'
import hashlib, json, subprocess, sys
from pathlib import Path
sys.path.insert(0, ".")
from app.services import engine_nuclei as e, nuclei_lock
manifest = e.verify_templates()                         # every template present, none extra, every SHA-256 equal
lock = nuclei_lock.load_lock()
for key, platform in lock["platforms"].items():
    assert len(platform["zip_sha256"]) == 64 and len(platform["binary_sha256"]) == 64, f"lock file does not pin {key}"
repo = Path("..")
folder = "backend/app/data/nuclei/templates"
tracked = set(subprocess.run(["git", "ls-files", folder], cwd=repo, capture_output=True, text=True, check=True).stdout.split())
expected = {f"{folder}/{n}" for n in manifest["templates"]} | {f"{folder}/MANIFEST.json", f"{folder}/LICENSE.md"}
missing = sorted(expected - tracked)
assert not missing, f"{len(missing)} vendored files are not in git: {missing[:5]}"
print(f"Nuclei manifest OK: {len(manifest['templates'])} templates, all tracked, both platforms pinned, commit {manifest['commit'][:8]}")
'@
  Push-Location (Join-Path $temp "backend")
  try { $check | & $python - } finally { Pop-Location }
}

Step "6. Backend tests" {
  Push-Location (Join-Path $temp "backend")
  try {
    if ($Fast) { & $python -m pytest -q -p no:cacheprovider tests/test_nuclei_validator.py tests/test_nuclei_mapping.py tests/test_nuclei_quick.py tests/test_nuclei_runner_engine.py tests/test_migrations.py tests/test_ownership.py tests/test_manual_verification.py }
    else { & $python -m pytest -q -p no:cacheprovider }
  } finally { Pop-Location }
}

if (-not $SkipFrontend) {
  Step "7a. Frontend: npm ci" { Push-Location (Join-Path $temp "frontend"); try { npm ci --silent --no-audit --no-fund } finally { Pop-Location } }
  Step "7b. Frontend: npm test" { Push-Location (Join-Path $temp "frontend"); try { npm test --silent } finally { Pop-Location } }
  Step "7c. Frontend: npm run build" { Push-Location (Join-Path $temp "frontend"); try { npm run build --silent } finally { Pop-Location } }
}

Write-Host ""
Write-Host "================ FRESH CLONE CHECK ================" -ForegroundColor Cyan
$results.GetEnumerator() | ForEach-Object { Write-Host ("{0,-46} {1}" -f $_.Key, $_.Value) }
if ($Keep) { Write-Host "Kept: $temp" } else { Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue }
if ($failed) { Write-Host "RESULT: FAILED" -ForegroundColor Red; exit 1 }
Write-Host "RESULT: PASSED" -ForegroundColor Green
exit 0
