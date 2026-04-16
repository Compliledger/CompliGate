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
User → CompliGate Backend → Proof Bundle → User executes tx on XRPL → POST /v1/settle/verify → Post-settlement verification
```

- **XRPL** is the settlement layer. CompliGate does not submit or broker transactions — it operates as a non-intermediary verifier.
- Users obtain a permit, independently execute the transaction on XRPL, then submit the XRPL transaction hash back to CompliGate for post-settlement verification.
- CompliGate checks that the settled transaction conforms to the permit constraints (amount, currency, counterparty, action type).

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
| `POST` | `/v1/settle/verify` | Post-settlement verification: checks an XRPL transaction against permit constraints |
| `GET` | `/v1/xrpl/health` | Returns whether the XRPL network is configured and reachable |

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

**POST /v1/settle/verify** — request body:
```json
{
  "tx_hash": "<xrpl-tx-hash>",
  "bundle": { ... },
  "signature": "<base64>"
}
```

---

## Proof Bundle

A Proof Bundle is the output of a successful permit issuance. It contains:

- **Canonical JSON** — deterministic key ordering ensures consistent serialization
- **Ed25519 signature** — signs the canonical bundle bytes; verifiable with the public key from `/public-key`
- **SHA-256 hash** (`bundle_hash`) — derived from the canonical JSON; used as the on-chain reference
- **Time-bound validity** — `iat` (issued-at) and `exp` (expiry) Unix timestamps embedded in the bundle
- **Post-settlement verification** — after a user independently executes a transaction on XRPL, CompliGate verifies the outcome against the permit constraints

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
| `XRPL_RPC_URL` | XRPL JSON-RPC URL for settlement verification (default: XRPL Testnet) |
| `XRPL_NETWORK` | XRPL network name used in verification metadata (e.g., `xrpl_testnet`) |

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

**Current phase**
- XRPL integration: post-settlement verification for RLUSD payments and trustline operations
- Frontend settlement verification flow

**Next phase**
- Production XRPL mainnet support
- Extended RLUSD compliance controls

---

CompliGate enforces policy at execution and produces cryptographic proof of authorization.
