# CompliGate

CompliGate is the transaction-time authorization and execution control layer of CompliLedger. It issues time-bound, cryptographically signed permits that determine whether a transaction is allowed, define how it may execute, and specify when it is valid.

## Repository Structure

- `backend/` — FastAPI service that issues and verifies signed Proof Bundles (Ed25519), with post-settlement verification against the XRP Ledger
- `frontend/` — UI for requesting permits, displaying proof summaries, verifying authorization status, and verifying XRPL settlement outcomes

## Backend

See [`backend/README.md`](backend/README.md) for full documentation including API reference, Proof Bundle format, environment variables, and deployment instructions.

## Quickstart

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

## Frontend

### Prerequisites

Node.js 18+ and npm.

### Development

```bash
cd frontend
cp .env.example .env          # set VITE_API_BASE to the backend URL
npm install
npm run dev                   # http://localhost:5173
```

### Production build

```bash
cd frontend
npm install
VITE_API_BASE=https://your-api.example.com npm run build
# Serve the dist/ directory with any static-file host (Nginx, S3, Vercel, etc.)
```

**Required environment variable:**

| Variable | Description |
|---|---|
| `VITE_API_BASE` | URL of the CompliGate backend (e.g. `https://api.example.com`). If not set, falls back to `http://localhost:8000`. |

> **Note:** `VITE_API_BASE` is baked into the JS bundle at build time by Vite. Set it before running `npm run build`.
