# CompliGate Backend

CompliGate is the transaction-time authorization and execution control layer of CompliLedger. It issues time-bound, cryptographically signed permits that determine whether a transaction is allowed, define how it may execute, and specify when it is valid. Each permit is packaged as a Proof Bundle — a canonical JSON document signed with Ed25519 and hashed for on-chain anchoring.

---

## Core Model

### Authorization (Before Execution)
CompliGate evaluates incoming requests against configured policy before any transaction proceeds.
- Subject identity is bound to the permit at issuance
- Policy version and jurisdiction are embedded in every bundle
- Requests that fail policy evaluation receive an explicit DENY

### Execution Constraints (During Execution)
The permit defines the conditions under which the transaction may proceed.
- Permitted action type (e.g., `transfer`, `trustline`)
- Currency and issuer binding
- Optional amount ceiling

### Validity Window (Time-Bound Control)
Each permit carries a hard expiry enforced at both issuance and verification.
- Default TTL: 5 minutes from issuance (`iat` → `exp`)
- Expired permits are rejected at `/v1/verify` and `/v1/commit`
- Time bounds are included in the signed payload and cannot be altered without invalidating the signature

---

## Architecture

```
User → CompliGate Backend → Proof Bundle → bundle_hash → Algorand Adapter → On-chain anchoring
```

- **Algorand** is the current proof anchoring layer. The `bundle_hash` (SHA-256 of the canonical bundle) is submitted to an Algorand adapter service which records it on-chain.
- **XRPL integration** is a planned future phase. CompliGate will connect to XRPL trustline and payment flows once the anchoring layer is stable.

---

## Role Within CompliLedger

CompliGate operates exclusively at the point of execution. It does not perform:
- Asset or transaction classification
- Reserve or collateral validation
- Identity verification or KYC

It consumes validated inputs provided by upstream CompliLedger components and returns a binary authorization decision: **ALLOW** or **DENY**, backed by a cryptographic Proof Bundle.

---

## API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Returns `{"status": "ok"}` |
| `GET` | `/public-key` | Returns the Ed25519 public key (base64 and hex) used to verify permit signatures |
| `POST` | `/v1/permit` | Issues a signed Proof Bundle for the given subject and action |
| `POST` | `/v1/verify` | Verifies a Proof Bundle signature and checks expiry |
| `POST` | `/v1/commit` | Records a permit commitment; forwards `bundle_hash` to the Algorand adapter for on-chain anchoring |
| `GET` | `/v1/adapter-health` | Returns whether the Algorand adapter is configured and reachable |

**POST /v1/permit** — request body:
```json
{
  "subject": "r...",
  "action": "transfer",
  "amount": 1000.00
}
```

**POST /v1/verify** — request body:
```json
{
  "bundle": { ... },
  "signature": "<base64>"
}
```

**POST /v1/commit** — request body:
```json
{
  "bundle_hash": "<sha256-hex>",
  "subject": "r...",
  "policy_id": "RLUSD_US_v1",
  "exp": 1234567890,
  "action": "transfer"
}
```

---

## Proof Bundle

A Proof Bundle is the output of a successful permit issuance. It contains:

- **Canonical JSON** — deterministic key ordering ensures consistent serialization
- **Ed25519 signature** — signs the canonical bundle bytes; verifiable with the public key from `/public-key`
- **SHA-256 hash** (`bundle_hash`) — derived from the canonical JSON; used as the on-chain reference
- **Time-bound validity** — `iat` (issued-at) and `exp` (expiry) Unix timestamps embedded in the bundle
- **On-chain anchor** — `bundle_hash` is submitted to the Algorand adapter and recorded in a transaction

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `POLICY_VERSION` | Policy identifier embedded in every Proof Bundle (e.g., `RLUSD_US_v1`) |
| `JURISDICTION` | Jurisdiction code included in the bundle (e.g., `US`) |
| `CURRENCY` | Currency code bound to the permit (e.g., `RLUSD`) |
| `ISSUER_ADDRESS` | Issuer address bound to the permit |
| `COMPLIGATE_PRIVATE_KEY_B64` | Base64-encoded Ed25519 seed (32 bytes). If blank, an ephemeral key is generated on startup. |
| `CORS_ORIGINS` | Comma-separated list of allowed CORS origins |
| `ALGORAND_ADAPTER_URL` | URL of the Algorand adapter service used for on-chain anchoring |

Copy `.env.example` to `.env` and fill in values before running locally.

---

## Running Locally

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`. Interactive docs are at `http://localhost:8000/docs`.

---

## Testing

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest tests/
```

---

## Docker

```bash
cd backend
docker build -t compligate-backend .
docker run --env-file .env -p 8000:8000 compligate-backend
```

---

## Roadmap

**Near term**
- Backend service stabilization and full test coverage
- Frontend permit request and verification UI
- Algorand on-chain anchoring via adapter service

**Next phase**
- XRPL integration: trustline authorization, payment gating, and token flow controls

---

CompliGate enforces policy at execution and produces cryptographic proof of authorization.
