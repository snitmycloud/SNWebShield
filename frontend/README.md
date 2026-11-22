# SNWebShield Frontend

React + Vite admin console for the local SNWebShield FastAPI backend.

## Included pages

- Overview dashboard with live client and website counts
- Client list, search and create-client form
- Website list, search and create-website form
- API connectivity indicator and retry handling
- Website authorisation status display (new records remain pending)
- Administrator login, session restoration and logout
- Authorisation list, search, filters, details, private evidence review, decision forms and audit history
- Monitoring consent/configuration, explicit activation, HTTP/DNS/TLS metrics, response-time chart, job/attempt history, incidents and notifications

This is an internal local-development UI with bearer tokens stored in sessionStorage. It does not include tenant isolation, multiple roles, an authorisation creation form, scanners or production session protections. Session-expiry handling and website status presentation have been updated; see [the correctness guide](../docs/AUTHORIZATION_CORRECTNESS.md) for behaviour, tests and remaining browser verification. Do not expose it publicly or enter real client secrets.

## Requirements

- Node.js 20.19+ or 22.12+
- npm
- SNWebShield FastAPI backend running at `http://127.0.0.1:8000`

## Setup on Windows (UCRT64 / Git Bash)

From the project root:

```bash
cd frontend
cp .env.example .env
npm install
npm run dev
```

For a new checkout, prefer `npm ci` over `npm install` to reproduce `package-lock.json`. Copy the environment example only if `.env` does not already exist. Configure the backend JWT key and create an administrator for a new installation using the [backend setup](../backend/README.md), then sign in through the UI.

Open the Vite address printed in the terminal (normally `http://127.0.0.1:5173`).

Keep the backend running in a separate terminal:

```bash
cd ../backend
source .venv/Scripts/activate
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The backend's `.env` must allow the frontend origin. The supplied backend example already includes `http://localhost:5173` and `http://127.0.0.1:5173` in `CORS_ORIGINS`. If the frontend is opened on a different origin, add that exact origin to the backend `CORS_ORIGINS` value and restart FastAPI.

## API integration

By default the frontend calls:

- `GET /api/v1/health`
- `GET /api/v1/clients?limit=100&offset=0`
- `POST /api/v1/clients`
- `GET /api/v1/websites?limit=100&offset=0`
- `POST /api/v1/websites`
- `POST /api/v1/auth/login` and `GET /api/v1/auth/me`
- `GET /api/v1/authorizations` and `GET /api/v1/authorizations/{id}/events`
- `POST /api/v1/authorizations/{id}/approve`, `/reject` and `/revoke`

Protected requests include a bearer token. `api.js` also has an authorisation creation helper, but no UI creation form calls it yet. The helper retrieves all pages for the current local UI. Authorisation summary counts come from the whole-dataset backend summary endpoint. Server-side UI pagination remains future scaling work.

## Validation

Run `npm run build` from `frontend`. A successful build does not verify browser workflows. `npm test` runs session/API helper regressions. `npm run test:e2e` runs eight Playwright journeys using a disposable backend on port 18000 and Vite on 15173. Install Chromium with `npx playwright install chromium` first. Chromium launch was blocked by a local socket restriction in the review environment; run it on Windows as described in the correctness guide.

Override the API base URL by editing `.env`:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1
```

Restart Vite after changing `.env`.

## Local authorisation evidence milestone

Private document upload, authenticated retrieval, human reviews, retention/holds and the approval evidence gate are implemented for local testing. Follow [the evidence guide](../docs/AUTHORIZATION_EVIDENCE.md) for migration `0003_evidence`, configuration, API details, backup limitations and Windows validation. See the monitoring guide for current validation limits; no GitHub push is required.

## Monitoring dashboard

Open **Monitoring** in the sidebar. Select a website, use its inspected/accepted monitoring permission document and save configuration; it remains disabled until explicitly enabled. Settings can be replaced, checks queued, execution disabled or consent revoked. The dashboard polls every 15 seconds and distinguishes stopped processes, stale samples, blocked destinations and measured failures. History uses 50-row pages.

Run the three independent backend operational processes for real checks. [Monitoring setup and acceptance](../docs/MONITORING.md) explains the workflow, status semantics and limitations. The browser test server substitutes a synthetic probe outcome through the actual job engine; it never monitors synthetic domains. `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` optionally selects an already-installed Chromium executable for tests. Leave it unset on Windows when using Playwright's installed Chromium.

## Security Scanner Worker: stage one

Explicit assessment requests, a versioned policy-only profile, live authorisation/evidence enforcement and an independent `assessment-worker` role now use the existing shared job engine. The Assessments dashboard supports request history, detail and cancellation. Migration `0005_assessment_intents` preserves existing monitoring data. No network check, Nmap, Nuclei or ZAP adapter is enabled; completed means permission preflight only.

See [the assessment audit, design, API and Windows acceptance guide](../docs/SCANNER_STAGE_ONE.md). Keep existing accounts, configuration and data; back up before migrating. New browser acceptance remains pending on Windows.
