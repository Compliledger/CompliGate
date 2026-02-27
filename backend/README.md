# CompliGate Backend (MVP)

CompliGate issues **time-bound, cryptographically signed compliance permits** ("Proof Bundles") for XRPL flows.

## What it does
- Generates a Proof Bundle with:
  - issuer + currency binding
  - policy version
  - custody/reserve attestation hashes (mocked for MVP)
  - expiry (5 minutes)
- Canonically serializes JSON and signs with Ed25519
- Returns a human-readable summary + raw JSON bundle + signature

## Endpoints
- `GET /health`
- `GET /public-key`
- `POST /permit` with `{ "subject": "r..." }`

## Local run (macOS)
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
uvicorn main:app --reload --port 8000
