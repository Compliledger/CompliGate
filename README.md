# CompliGate

CompliGate is the transaction-time authorization and execution control layer of CompliLedger. It issues time-bound, cryptographically signed permits that determine whether a transaction is allowed, define how it may execute, and specify when it is valid.

## Repository Structure

- `backend/` — FastAPI service that issues and verifies signed Proof Bundles (Ed25519), with on-chain anchoring via Algorand
- `frontend/` — UI for requesting permits, displaying proof summaries, and verifying authorization status

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
