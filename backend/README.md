# SNWebShield Backend (Milestone 2A)

Local development API for client and website registration.

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
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

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

Use the interactive docs at `/docs` to:

1. `POST /api/v1/clients` to register a client.
2. `GET /api/v1/clients` to list clients.
3. `POST /api/v1/websites` to register a website for a client.
4. `GET /api/v1/websites?client_id=1` to list that client's websites.

Website registration always sets `authorisation_status` to `pending`. Registering a URL is not permission to test it. This milestone does not include scanning functionality or client authentication.

## Tests

From the `backend` folder, with the virtual environment activated:

```bash
pytest -q
```

## Important development limits

This is a local development MVP, not production-ready. It currently has no login, role-based access control, tenant isolation, audit log, authorisation-document workflow, or scanner integration. Keep it bound to `127.0.0.1`; do not expose it to the internet or store real client secrets or sensitive assessment evidence until those controls are implemented and reviewed.

Before production use, add authentication, authorisation, tenant isolation, database migrations (Alembic), secure evidence storage, audit logging, backups, rate limits, and security testing.
