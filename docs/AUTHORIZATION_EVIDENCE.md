# Authorisation Evidence Management — local implementation

This incremental change builds on the tested authentication/authorisation correctness implementation. GitHub is not required for local development. The review workspace baseline is `3a6cb3a` (a local snapshot); the user's independently committed Windows baseline is `6d2299f`. They are not claimed to be identical commits. Run `git apply --check` before applying the patch, and stop on a mismatch. No push or merge is required.

## Data and workflow

Migration `0003_evidence` adds three tables: authorization_evidence, evidence_reviews and evidence_events. It adds evidence_revision to authorisations and evidence_review_id to authorisation decision events. Existing accounts, windows, statuses, evidence-review attestations and audit history are preserved. Historical decision events have no linked evidence review; old approvals are not silently rewritten or represented as having uploaded documents.

Every new approval requires stored evidence and a current accepted human review by the approving administrator. The review names the entire current evidence set, its revision, reviewer, timestamp and comments. Each document must have been downloaded or previewed through the authenticated endpoint by that reviewer first. Explicit inspection attestation is mandatory. This records a human's declaration, not proof that they carefully read it, verified the signatory's authority, or cryptographically validated a signature.

Upload, withdrawal and new reviews change the revision; competing approval uses a conditional revision/status update. A newer upload or rejected review invalidates earlier approval eligibility. File integrity is checked on access, review and approval. Approval and its exact evidence-review reference are committed in the same transaction as the authorisation audit event. Evidence acceptance does not approve the authorisation automatically, and no action starts a scan.

Only active users with the existing admin role may use any evidence route. All current administrators share this internal workspace; this is not tenant isolation or multi-role RBAC. No client portal or new user roles are introduced.

## Private storage and validation

Default storage: the backend service user's home directory under `SNWebShield-Private/evidence`, outside the repository. Configure an absolute private `EVIDENCE_ROOT` if needed. Repository paths and symlinked storage paths are rejected. Use a private user-owned directory; on Windows verify its NTFS permissions and use BitLocker/encrypted volumes where required. POSIX mode restrictions are applied where supported; chmod is not a replacement for Windows ACL configuration.

Files use generated UUID names, never caller filenames. Original display filenames are bounded and reject path separators/control characters. SHA-256, actual media type, size, uploader ID, upload time, client/website/authorisation IDs and retain-until time are stored. Ownership is derived by the server rather than accepted from upload fields. No filesystem paths are returned by the API.

Upload is a streamed binary POST body with `X-Evidence-Filename` holding the percent-encoded display filename. It is not multipart; the server enforces the byte limit as it reads, without parsing an unlimited multipart body first. The frontend attaches the existing bearer token in a header. The default limit is 10 MiB, configurable with EVIDENCE_MAX_BYTES (maximum configuration 25 MiB).

Allowed formats: PDF, PNG, JPEG. Extension, file signature, and actual parser/decoder must agree. Empty, malformed, encrypted PDFs, PDFs over 100 pages, excessive object complexity and detected active/embedded content are rejected. Images must decode, use the expected format, contain one frame and not exceed 20 million pixels. SHA-256 is verified before returning content.

Original files are attachment downloads with no-store/private caching, nosniff and restrictive CSP. Tokens never appear in download URLs. Images have separately generated RGB PNG previews without original metadata. PDFs download for inspection; inline PDF preview is deliberately unavailable. The original bytes are preserved rather than rewritten, avoiding accidental invalidation of digital signatures.

These controls are not antivirus certification or a guarantee that every malicious document is detected. Dedicated malware scanning, sandboxed parser/rendering processes with OS-level resource limits, production upload rate/quota controls and encryption/key management remain hardening work. This milestone is a local internal-admin implementation, not an internet-ready evidence intake service.

## Retention, withdrawal, holds and deletion

Default retention is 365 days after the later of upload time or the recorded authorisation end date. EVIDENCE_RETENTION_DAYS is configurable for new uploads; this is a development policy, not a legal retention mandate. Agree the actual policy for client engagements before real use. Changing configuration does not shorten existing stored retain-until dates.

Withdrawal makes a document unavailable for access/review without deleting its bytes or history. Evidence supporting an approved authorisation cannot be withdrawn or purged until the authorisation is revoked. Legal holds block purge even after retention expires. Hold changes and deletion require a reason of at least 10 trimmed characters.

Purge is explicit, authenticated and allowed only for withdrawn evidence after retention, with no hold and no approved authorisation. It records deletion_pending before removing bytes, then records a purged tombstone. If disk deletion fails, downloads remain blocked and an administrator can retry. Metadata, review records and events remain available. There is no unaudited hard-delete route for history.

Ordinary handled upload failures remove uncommitted bytes. A process/host crash during upload may leave an unreferenced UUID file; reconcile orphan files through a reviewed operational procedure rather than deleting arbitrary private-directory contents. Backups require a retention/deletion policy too. The SQLite backup command backs up the database only: take a coordinated private copy of the evidence directory as well before real evidence use.

## API inventory (all under /api/v1 and admin authenticated)

| Method and path | Purpose |
|---|---|
| POST /authorizations/{id}/evidence | Stream a PDF/PNG/JPEG upload; pending authorisations only |
| GET /authorizations/{id}/evidence | Documents, complete review history and current evidence revision |
| GET /authorizations/{id}/evidence/events | Evidence upload/access/review/withdrawal/hold/deletion history |
| GET /evidence/{uuid}/download | Verify hash, audit access and download original bytes |
| GET /evidence/{uuid}/preview | Verify original and return safe generated PNG for images |
| POST /authorizations/{id}/evidence/reviews | Revision, accepted/rejected decision, inspected=true and >=20-character comment |
| POST /evidence/{uuid}/withdraw | Withdraw with a reason; never discard history |
| POST /evidence/{uuid}/hold | Set/release legal_hold with a reason |
| POST /evidence/{uuid}/purge | Retention-checked, auditable deletion with a reason |

Successful access and mutations have evidence events; approval/rejection/revocation retain their existing decision audit trail. Failed unauthenticated requests have no valid actor to attribute to an evidence event. General authentication/security-event logging and database-enforced immutable audit storage remain broader platform work.

## Apply on Windows locally — PowerShell

Stop the existing backend and frontend servers first. Keep `.env`, existing administrators and application data.

Download and extract `SNWebShield_Authorization_Evidence.zip` to Downloads, then run:

```powershell
Set-Location C:\SNWebShield-Local
git status --short --branch
git log -1 --oneline
git switch -c feature/authorization-evidence
$patchPath = "$HOME\Downloads\SNWebShield_Authorization_Evidence\authorization-evidence.patch"
git apply --check $patchPath
```

Only if the check succeeds:

```powershell
git apply $patchPath
git diff --check
Set-Location C:\SNWebShield-Local\backend
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m app.cli.backup_database
```

After the backup succeeds:

```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m alembic current
.\.venv\Scripts\python.exe -m pytest -q
Set-Location C:\SNWebShield-Local\frontend
npm ci
npm test
npm run build
npm run test:e2e
```

Expected database head is `0003_evidence`. Existing approval tests now create, open and review actual synthetic documents rather than bypassing the evidence gate. Browser tests start their own temporary database and private evidence directory on separate ports; they do not use real client evidence. Browser execution must pass locally before accepting this milestone. A build/test-list result is not a browser test pass.

Start the normal servers as before and open an authorisation. Upload a signed document, preview an image or download the PDF, inspect it, enter evidence-review comments, attest inspection and record accepted/rejected evidence review. Accepted current review enables the existing approve action; an additional approval note/attestation is still required. Rejected evidence leaves approval disabled; the existing rejection action records the authorisation decision.

Do not turn existing legacy date flags on through SQL. Legacy windows still require re-establishment from original permission as documented in AUTHORIZATION_CORRECTNESS.md. There is no new authorisation-creation form; the existing authenticated POST authorisation API remains available.

No push is needed. When local validation is satisfactory, stage only CHANGED_FILES.txt from the package and commit locally if desired. Keep uploaded documents, backups, secrets and databases outside Git. PostgreSQL integration, updated browser execution and production hardening must not be claimed as verified here.
