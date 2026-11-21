# SNWebShield Frontend — Milestone 2B

React + Vite admin console for the local SNWebShield FastAPI backend.

## Included pages

- Overview dashboard with live client and website counts
- Client list, search and create-client form
- Website list, search and create-website form
- API connectivity indicator and retry handling
- Website authorisation status display (new records remain pending)

This is an internal local-development UI. It does not include authentication, tenant isolation, permission management, scanning controls or production hardening. Do not expose it publicly or enter real client data until those controls are implemented.

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

Override the API base URL by editing `.env`:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1
```

Restart Vite after changing `.env`.
