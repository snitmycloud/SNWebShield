# SNWebShield Frontend

React + Vite admin console for the local SNWebShield FastAPI backend.

## Included pages

- Overview dashboard with live client and website counts
- Client list, search and create-client form
- Website list, search and create-website form
- API connectivity indicator and retry handling
- Website authorisation status display (new records remain pending)
- Administrator login, session restoration and logout
- Authorisation list, search, filters, details, decision forms and audit history

This is an internal local-development UI with bearer tokens stored in sessionStorage. It does not include tenant isolation, multiple roles, an authorisation creation form, evidence uploads, scanners or production session protections. Session-expiry handling and website status presentation have been updated; see [the correctness guide](../docs/AUTHORIZATION_CORRECTNESS.md) for behaviour, tests and remaining browser verification. Do not expose it publicly or enter real client secrets.

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

Run `npm run build` from `frontend`. A successful build does not verify browser workflows. `npm test` runs session/API helper regressions. `npm run test:e2e` runs six Playwright journeys using a disposable backend on port 18000 and Vite on 15173. Install Chromium with `npx playwright install chromium` first. Browser execution remains pending in the review environment; run it on Windows as described in the correctness guide.

Override the API base URL by editing `.env`:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1
```

Restart Vite after changing `.env`.
