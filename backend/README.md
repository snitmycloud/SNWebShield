# SNWebShield Backend

Local development API for administrator authentication, client and website registration, and authorisation review with decision audit events.

## Requirements

- Python 3.11 or newer
- Git
- Windows users can use PowerShell, Git Bash, or UCRT64.

## Run locally on Windows (Git Bash / UCRT64)

From the repository root:

```bash
cd backend
python -m venv .venv
source .venv/Scripts/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

Copy the example only when creating a new local configuration; do not overwrite an existing `.env`. The committed backend example omits JWT settings. Generate a development signing secret locally:

```bash
python -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Add the generated value to `JWT_SECRET_KEY` in `backend/.env`. Do not paste it into chat or commit it. The key must be at least 32 bytes. Optional settings are `JWT_ACCESS_TOKEN_MINUTES` (default 20), `JWT_ISSUER` (default `snwebshield-api`) and `JWT_AUDIENCE` (default `snwebshield-admin`). The older root example's `SECRET_KEY` is not the backend's JWT setting.

For a new installation only, create an administrator interactively, then start the API:

```bash
python -m alembic upgrade head
python -m app.cli.create_admin
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Keep an existing administrator and database. No account reset is required. See [PowerShell instructions](LOCAL_SETUP.md) for the equivalent commands.

If `python` is not recognised in Git Bash, use `py -3` to create the virtual environment:

```bash
py -3 -m venv .venv
source .venv/Scripts/activate
```

Open these local addresses:

- API health: http://127.0.0.1:8000/api/v1/health
- Interactive API docs: http://127.0.0.1:8000/docs

The default database is SQLite at `backend/snwebshield_dev.db`, so no separate database server is needed for this first local milestone. PostgreSQL can be configured later using `DATABASE_URL` in `.env`.

## First API operations

Use the interactive docs at `/docs` to sign in with `POST /api/v1/auth/login`, then use **Authorize** with the returned bearer token. Do not share the token. Protected operations include:

1. `POST /api/v1/clients` to register a client.
2. `GET /api/v1/clients` to list clients.
3. `POST /api/v1/websites` to register a website for a client.
4. `GET /api/v1/websites?client_id=1` to list that client's websites.

Website registration always sets `authorisation_status` to `pending`. Registering a URL is not permission to test it. This milestone does not include scanning functionality or client authentication.

Authorisation routes support creation, listing by website/status, detail retrieval, audit history, approval, rejection and revocation. Approval requires `evidence_reviewed: true` and a trimmed review note of at least 20 characters. Rejection/revocation require a trimmed reason of at least 10 characters. The evidence flag is an administrator attestation; the new evidence subsystem additionally requires stored documents and a current accepted human review. Cryptographic signature verification is not implemented. Approval does not launch a scan.

See [the correctness guide](../docs/AUTHORIZATION_CORRECTNESS.md) for the implemented UTC policy, effective states, atomic transitions and legacy-date migration. An `approved` database flag is not a sufficient execution permission.

## Tests

From the `backend` folder, with the virtual environment activated:

```bash
pytest -q
```

## Important development limits

This is a local development MVP, not production-ready. Administrator login and authorisation decision audit events exist. Multiple roles, tenant isolation, global API rate limiting, secure cookie sessions and scanners do not. Private evidence, operational audit events and monitoring execution throttles are implemented. Keep it bound to `127.0.0.1`; do not expose it to the internet or store real client secrets or sensitive assessment evidence until the necessary controls are implemented and reviewed.

Before production use, add tenant isolation, encrypted evidence storage/backups, broader audit coverage, global API rate limits and production authentication controls. Startup requires the migrated schema and does not recreate it. Run `python -m alembic upgrade head` from backend. Existing installations must first make a verified backup with `python -m app.cli.backup_database`; see the correctness guide. Do not reset an existing administrator.

## Local authorisation evidence milestone

Private document upload, authenticated retrieval, human reviews, retention/holds and the approval evidence gate are implemented for local testing. Follow [the evidence guide](../docs/AUTHORIZATION_EVIDENCE.md) for migration `0003_evidence`, configuration, API details, backup limitations and Windows validation. See the monitoring guide for current validation limits; no GitHub push is required.

## Monitoring worker

Migration `0004_monitoring` adds the shared job engine and monitoring tables. Run the API, `python -m app.cli.operations scheduler`, `python -m app.cli.operations worker` and `python -m app.cli.operations notifications` independently from `backend`, using the same private configuration/database/evidence directory. Each operations command supports `--once`. The API never probes websites inline.

See [monitoring design, permissions, limits, APIs and Windows checks](../docs/MONITORING.md). Consent is separate from VAPT approval, configuration saves disabled, and DNS/redirect checks cannot permit private destinations. Notifications default to the dashboard; SMTP is optional private operator configuration.

## Security Scanner Worker: stage one

Explicit assessment requests, a versioned policy-only profile, live authorisation/evidence enforcement and an independent `assessment-worker` role now use the existing shared job engine. The Assessments dashboard supports request history, detail and cancellation. Migration `0005_assessment_intents` preserves existing monitoring data. No network check, Nmap, Nuclei or ZAP adapter is enabled; completed means permission preflight only.

See [the assessment audit, design, API and Windows acceptance guide](../docs/SCANNER_STAGE_ONE.md). Keep existing accounts, configuration and data; back up before migrating. New browser acceptance remains pending on Windows.
