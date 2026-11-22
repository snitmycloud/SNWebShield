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

Authorisation routes support creation, listing by website/status, detail retrieval, audit history, approval, rejection and revocation. Approval requires `evidence_reviewed: true` and a trimmed review note of at least 20 characters. Rejection/revocation require a trimmed reason of at least 10 characters. The evidence flag is an administrator attestation; there is no signed-document upload or verification subsystem. Approval does not launch a scan.

See [the correctness guide](../docs/AUTHORIZATION_CORRECTNESS.md) for the implemented UTC policy, effective states, atomic transitions and legacy-date migration. An `approved` database flag is not a sufficient execution permission.

## Tests

From the `backend` folder, with the virtual environment activated:

```bash
pytest -q
```

## Important development limits

This is a local development MVP, not production-ready. Administrator login and authorisation decision audit events exist. Multiple roles, tenant isolation, general audit logging, document evidence storage, rate limiting, secure cookie sessions and scanners do not. Keep it bound to `127.0.0.1`; do not expose it to the internet or store real client secrets or sensitive assessment evidence until the necessary controls are implemented and reviewed.

Before production use, add tenant isolation, secure evidence storage, general audit logging, backup operations, rate limits and production authentication controls. Startup requires the migrated schema and does not recreate it. Run `python -m alembic upgrade head` from backend. Existing installations must first make a verified backup with `python -m app.cli.backup_database`; see the correctness guide. Do not reset an existing administrator.
