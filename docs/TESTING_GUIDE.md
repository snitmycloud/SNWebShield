# Testing guide

## Automated tests

Run one command at a time (running several together can exhaust memory on this computer).

| Level | Command | Time | Use it |
|---|---|---|---|
| **Quick** | `powershell -File scripts\test-quick.ps1` (backend `pytest -m "not slow"` + frontend tests) | about 1 minute | while you work |
| **Full** | `powershell -File scripts\test-full.ps1` (all backend tests, in parallel with pytest-xdist, + frontend tests + build) | about 1 minute (5 minutes without xdist) | before every commit you want to trust |
| **Release** | `powershell -ExecutionPolicy Bypass -File scripts\fresh-clone-check.ps1` | about 5 minutes | once at the end of each phase, before merging |

By hand: `cd backend; .\.venv\Scripts\python.exe -m pytest` (full), add `-m "not slow"` for quick or `-n 6` for parallel (needs `pip install -r requirements-dev.txt`, dev-only). `cd frontend; npm test; npm run build`.

The fresh-clone check clones the committed branch to a temporary folder, installs from scratch, verifies the Nuclei manifest and that `.gitignore` hides nothing needed, then runs the backend and frontend tests and the build.

**Why it is fast.** The database schema is built once per test run and every test starts from a copy of it (it used to be created and dropped for each of 1,200 tests, about 1.4 s each). The test database skips disk syncing. A few waits are shortened for tests (the TLS handshake wait on plain-HTTP fixtures, closed ports that refuse at once). Tests that need real time (process kills, scan time limits, slow servers) keep it. The slow ones (0.8 s or more) are listed in `backend/tests/slow_tests.txt` and carry the `slow` marker; refresh the list with `backend/tools/make_slow_list.py`.

Rules the tests follow:
- **No test touches the internet.** An autouse fixture limits connections to loopback test servers and replaces real DNS, crt.sh, NVD and OSV with fakes.
- **Every phase has security boundary tests:** verified, unverified and lost ownership; another user's websites; private and reserved addresses (`test_ip_policy.py`); worker timeout and cancellation.
- **Security hardening** (`test_security_hardening.py`): audit log, login throttling, logout revocation, forged tokens, password rules, headers, CORS, cross-user access, admin-only routes, no leaked error details.

## Testing by hand

Use only websites you are allowed to scan: `scanme.nmap.org` (approved test target, admin accounts only, 10 scans a day) and your own test site.

1. Sign up, confirm the email (saved as a file in the outbox folder until SMTP is set up).
2. Add a website, verify it (DNS, file or meta tag); the first scan starts by itself.
3. Open the website: Monitor, Detect, Vulnerabilities and Report tabs; try Re-scan to confirm fix, Accept risk and Stop accepting; run a second scan and read "Changes since last scan".
4. Settings: switch an alert type off, send a test alert (outbox).
5. Admin (admin account): change a plan; Workers shows every role.
6. Reboot test (after `scripts\install-autostart.ps1`): restart the computer, start nothing, and check Admin > Workers after two minutes.

Evidence from earlier runs is in `docs/proof/`.
