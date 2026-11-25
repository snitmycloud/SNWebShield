# SNWebShield Engineering & Security Rules
**Product Motto:** MONITORS. DETECTS. VALIDATES. PROTECTS.
**Local Repo:** `C:\SNWebShield-Local` (Windows / PowerShell) | **GitHub:** `https://github.com/snitmycloud/SNWebShield`
**Product spec:** `docs/SNWEBSHIELD_SPEC.md` — its section 1 rules apply to every task; work one phase at a time.

## Non-Negotiable Security Invariants
- Domain ownership verification (DNS TXT, file or meta tag) is the only approval step. Never scan a website unless the account that owns it has verified ownership; re-check ownership before every scan (24-hour cache) and pause scans when verification is lost.
- Start the first scan automatically only when ownership verification succeeds; never scan on registration alone. Immediately before execution, re-check the owner, the verification and the resolved IP.
- Prevent SSRF, DNS rebinding (resolve once per scan and pin that IP), unsafe HTTP redirects, and command injection. Never contact private, loopback, link-local, multicast, cloud-metadata or this server's own addresses.
- Treat all target HTTP responses, headers, and scanner outputs as untrusted data.
- Fail safe: a check that fails or times out is reported as "could not check" or "incomplete", never "safe" or "clean".
- Never print, log, or request passwords, `.env` contents, JWT secrets, tokens, or SSH private keys.
- Maintain complete audit logs for authentication, ownership checks, scans (user, website, IP, type, start, end, result), admin actions and remediation actions.

## Runtime Constraints
- Keep the React frontend and FastAPI backend running locally on Windows; do not deploy the full stack to Azure.
- Scans run in Python inside the existing worker (standard library plus packages already in the project). Do not add Nmap, Docker or VM execution; ask before adding any new package.
- The legacy Azure VM (`azureuser@57.159.27.58`) is not used by new code. Never expose Docker TCP port `2375`, create paid Azure resources, or delete existing VM containers, images, volumes or data without explicit approval.

## Development & Quality Workflow
- Reuse existing models, migrations, APIs, workers, and frontend components; never rebuild working features.
- Back up local database files before running schema migrations; preserve all existing data.
- For every phase: add migrations, backend unit/API tests, security boundary tests (verified, unverified and lost ownership; another user's websites; private/reserved IPs; worker timeout/cancellation), frontend tests, and verify the frontend production build.
- Commit verified phases locally on a feature branch; never push to GitHub or merge to `main` without explicit instruction.
- Update `docs/AUDIT_MATRIX.md` and `README.md` after every phase.
