# Testing guide

## Automated tests

Run one command at a time (running several together can exhaust memory on this computer).

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest                  # full backend suite
cd ..\frontend
npm test                                              # unit tests (Node test runner)
npm run build                                         # production build
```

**Before merging a phase:** `powershell -ExecutionPolicy Bypass -File scripts\fresh-clone-check.ps1`. It clones the committed branch to a temporary folder, installs from scratch, verifies the Nuclei manifest and that `.gitignore` hides nothing needed, then runs the backend and frontend tests and the build.

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
