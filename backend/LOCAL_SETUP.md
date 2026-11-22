# Local setup quick reference

Run the backend from the `backend` folder. Do not run `uvicorn` from the repository root.

The following Bash setup creates a new environment. For an existing installation, preserve `.env`, the administrator and the database; use the existing virtual environment and start Uvicorn. New installations must also configure `JWT_SECRET_KEY` and provision an administrator as described in [the backend README](README.md).

```bash
cd backend
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
cp .env.example .env
python -m alembic upgrade head
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

For UCRT64/Git Bash, the activation command above is appropriate after creating the venv with `python -m venv .venv` or `py -3 -m venv .venv`.

## Existing installation: PowerShell

Using the latest project location supplied for this review:

```powershell
Set-Location C:\SNWebShield-Local\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

In a second PowerShell terminal:

```powershell
Set-Location C:\SNWebShield-Local\frontend
npm run dev
```

For baseline checks, run these separately in the corresponding directories:

```powershell
# backend
.\.venv\Scripts\python.exe -m pytest -q
```

```powershell
# frontend
npm run build
```

If your checkout is still at the older `C:\SNWebShield_Project_Foundation\SNWebShield` location, substitute that root. These commands do not reset accounts or remove application data.

For an existing database, follow the backup and migration order in [the correctness guide](../docs/AUTHORIZATION_CORRECTNESS.md) before starting the updated API. Do not run an old application binary against the migrated database as a rollback procedure.

## Local authorisation evidence milestone

Private document upload, authenticated retrieval, human reviews, retention/holds and the approval evidence gate are implemented for local testing. Follow [the evidence guide](../docs/AUTHORIZATION_EVIDENCE.md) for migration `0003_evidence`, configuration, API details, backup limitations and Windows validation. See the monitoring guide for current validation limits; no GitHub push is required.

## Independent monitoring processes

After backing up the existing database **and private evidence files**, run `.\.venv\Scripts\python.exe -m alembic upgrade head` from `backend`. Expected head is `0004_monitoring`. Start the scheduler, worker and notification dispatcher in separate backend terminals using `python -m app.cli.operations scheduler`, `worker` and `notifications` with the existing venv Python. Leave the API and frontend running in their own terminals. Use Ctrl+C to stop each process.

Follow [the monitoring guide](../docs/MONITORING.md) for exact PowerShell commands, explicit consent/enable workflow and functional acceptance checks. No account reset or database recreation is needed.
