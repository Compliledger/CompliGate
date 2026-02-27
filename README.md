# CompliGate (XRPL)

CompliGate is a **compliance authorization layer** for XRPL-issued assets (e.g., RLUSD). It issues **time-bound, cryptographically signed Proof Bundles** (“permits”) that gate trustline creation and token transfers.

## What this repo contains
- `backend/` — FastAPI service that issues signed Proof Bundles (Ed25519) with a 5-minute expiry
- `frontend/` — UI to request a permit, display a human-readable proof summary + timer, and (later) attach the proof to XRPL TrustSet/Payment transactions

## Why it matters
XRPL supports issuer controls, but regulated markets need **policy-aware authorization**. CompliGate provides a reusable compliance primitive for permissioned liquidity and institutional participation.

## Quickstart (backend)
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --reload --port 8000
