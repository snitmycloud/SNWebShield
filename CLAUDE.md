# SNWebShield Engineering & Security Rules
**Product Motto:** MONITORS. DETECTS. VALIDATES. PROTECTS.
**Local Repo:** `C:\SNWebShield-Local` (Windows / PowerShell) | **GitHub:** `https://github.com/snitmycloud/SNWebShield` | **Remote Docker Host:** `azureuser@57.159.27.58`

## Non-Negotiable Security Invariants
- Never assess a website without explicit, non-expired, unrevoked written authorisation matching the exact domain scope and allowed methods.
- Never trigger scans automatically on website registration or authorisation approval; require an explicit assessment request and revalidate permission/UTC dates/scope immediately before execution.
- Prevent SSRF, DNS rebinding (pin resolved IPs), unsafe HTTP redirects, and command injection.
- Treat all target HTTP responses, headers, and scanner outputs as untrusted data.
- Require human analyst validation before marking any vulnerability confirmed or publishing any VAPT report.
- Never print, log, or request passwords, `.env` contents, JWT secrets, tokens, or SSH private keys.
- Maintain complete audit logs for authentication, evidence reviews, assessments, analyst decisions, and remediation actions.

## Azure & Docker Constraints
- Keep the React frontend and FastAPI backend running locally on Windows; do not deploy the full stack to Azure.
- Use `azureuser@57.159.27.58` strictly via SSH for remote Docker scanner execution; never expose Docker TCP port `2375` publicly.
- Run scanner containers with `--network none` (for header analysis), non-root user, read-only root filesystem, and strict CPU, memory, PID, and timeout limits.
- Record container execution time and resource usage; never fall back to unrestricted local host execution if Docker/SSH is unavailable.
- Never create paid Azure resources/registries or delete existing VM containers, images, volumes, or data without explicit approval.

## Development & Quality Workflow
- Reuse existing models, migrations, APIs, workers, and frontend components; never rebuild working features.
- Back up local database files before running schema migrations; preserve all existing data.
- For every milestone: add migrations, backend unit/API tests, security boundary tests (valid, expired, revoked, out-of-scope auth; worker timeout/cancellation; Docker isolation), frontend tests, and verify the frontend production build.
- Commit verified milestones locally on a feature branch; never push to GitHub without explicit instruction.
- Update `docs/AUDIT_MATRIX.md` and `README.md` after every milestone.

- Keep the scanner `Dockerfile` and analysis script version-controlled in the local repo; when modified, sync only that scanner build directory to `azureuser@57.159.27.58` via `scp` and rebuild the scanner image over SSH without touching other VM containers.