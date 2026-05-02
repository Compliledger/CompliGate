# CompliGate

### Deterministic Compliance Authorization for XRPL Transactions

CompliGate is an XRPL-focused authorization and verification layer that defines the conditions under which a transaction is allowed to execute, links that authorization to a real XRPL testnet transaction, and produces a proof artifact for auditability.

> CompliGate does not execute transactions as an intermediary. It generates authorization constraints and verifies settlement outcomes.

> Current status: working XRPL testnet prototype with real transaction roundtrip, memo-linked bundle hashes, settlement verification, and proof artifacts. Compliance provider is currently mock_trm pending live provider access.

<img src="https://img.shields.io/badge/status-XRPL%20Testnet%20MVP-blue" alt="Status: XRPL Testnet MVP">
<img src="https://img.shields.io/badge/network-XRPL%20Testnet-green" alt="Network: XRPL Testnet">
<img src="https://img.shields.io/badge/compliance-mock__trm-yellow" alt="Compliance: Mock Provider (mock_trm)">
<img src="https://img.shields.io/badge/backend-FastAPI-009688?logo=fastapi&logoColor=white" alt="Backend: FastAPI">
<img src="https://img.shields.io/badge/frontend-React-61dafb?logo=react&logoColor=black" alt="Frontend: React">
<img src="https://img.shields.io/badge/language-TypeScript-3178c6?logo=typescript&logoColor=white" alt="Language: TypeScript">
<img src="https://img.shields.io/badge/database-PostgreSQL-4169e1?logo=postgresql&logoColor=white" alt="Database: PostgreSQL">
<img src="https://img.shields.io/badge/signing-Ed25519-2ea44f" alt="Signing: Ed25519">

---

## Executive Summary

CompliGate is an **authorization and verification layer** for tokenized-asset activity on XRPL. Given a proposed transaction, it evaluates configured policy and compliance evidence (KYC, sanctions screening, reserve / 1:1 backing) and issues a short-lived, Ed25519-signed **Proof Bundle** that encodes:

- the **decision** (`ALLOW` / `DENY`),
- the **constraints** under which the transaction may proceed (action, currency, issuer, amount ceiling, validity window),
- a reference to the underlying **compliance evidence**, and
- a `bundle_hash` suitable for embedding in an XRPL transaction memo.

After the user independently settles the transaction on XRPL, CompliGate **verifies** the on-ledger transaction against the constraints in the bundle and returns a deterministic settlement-verification result.

CompliGate **does not custody assets, broker transactions, or submit settlement on behalf of users.** It is a verifier, not an executor.

---

## Why XRPL Needs This

XRPL is purpose-built for value movement. It provides **fast, deterministic settlement** and a mature **issued-asset infrastructure** — native trust lines, IOUs, and a built-in DEX — that make it a natural home for stablecoins and tokenized real-world assets. It also exposes **issuer-side controls and transaction capabilities** (e.g. issuer accounts, trust line authorization, freeze, `RequireAuth`, `DisallowXRP`, transfer fees, payment paths) that let an issuer shape *who* can hold an asset and *how* it can move.

What XRPL does **not** provide — and is not trying to provide — is the off-ledger compliance reasoning that regulated issuers and venues are now expected to perform on every transaction:

- Is this counterparty subject to sanctions or KYC restrictions?
- Is this asset properly **classified** (security, payment stablecoin, commodity-like token) for the jurisdictions involved?
- For a payment stablecoin (e.g. RLUSD), is the **1:1 reserve backing** currently attested?
- Is the transaction within the **jurisdiction**, currency, issuer, and amount limits the institution authorized?
- Can the institution later produce **verifiable, tamper-evident proof** that those checks were performed, and what they decided, for audit?

Regulated stablecoins and tokenized assets need **deterministic compliance logic** — the same inputs must always produce the same authorization decision, and that decision must be reconstructable after the fact. Emerging U.S. regulatory direction (SEC/CFTC tokenization guidance, the GENIUS Act for payment stablecoins, the CLARITY Act for market structure) is converging on the same expectations across jurisdictions: **asset classification, 1:1 backing attestation, jurisdiction controls, and end-to-end auditability** of every regulated transfer.

CompliGate **complements XRPL** by providing the **authorization and proof layer around XRPL execution**. It decides whether a proposed transaction is allowed under configured policy and compliance evidence *before* the user submits it, and after settlement it verifies the on-ledger transaction against that decision.

CompliGate does **not** change the XRPL protocol, does **not** require any amendment, and does **not** enforce policy on-ledger — XRPL still settles transactions exactly as it does today.

The enforcement boundary is the institution's submission path: only transactions accompanied by a valid, unexpired Proof Bundle are submitted, and the resulting on-ledger transaction is independently verifiable against the bundle via the embedded `bundle_hash` memo.

---

## Problem → Solution

| Problem                                                            | Solution                                                                       |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| Compliance checks are handled off-chain and inconsistently         | CompliGate generates deterministic authorization constraints                   |
| XRPL transactions do not automatically carry compliance context    | CompliGate links `bundle_hash` to XRPL transaction memo                        |
| Settlement verification is difficult to audit                      | CompliGate fetches the XRPL `tx_hash` and produces a proof artifact            |
| Sanctions/KYC/reserve providers may vary by institution            | CompliGate uses a provider abstraction layer; current MVP uses `mock_trm`      |
| Institutions need repeatable audit evidence                        | CompliGate stores permits, evidence context, and proof artifacts               |

---

## Demo Flow

```mermaid
flowchart LR
    A[Treasury Decision] --> B[CompliGate Evaluation]
    B --> C[Signed Permit + Constraints]
    C --> D[XRPL Testnet Execution]
    D --> E[Settlement Verification]
    E --> F[Proof Artifact]

    B --> B1[Asset Classification]
    B --> B2[Sanctions Provider Abstraction]
    B --> B3[Jurisdiction + Limits]
    D --> D1[Memo: bundle_hash]
    F --> F1[tx_hash]
    F --> F2[ledger_index]
    F --> F3[reason_codes]
```

This is the current MVP demo path: Treasury Decision → CompliGate Evaluation → Permit → XRPL Execution → Proof.

End-to-end happy path (real XRPL testnet, mocked sanctions provider in MVP):

```
   ┌──────────┐    1. POST /v1/permit          ┌────────────────┐
   │  Client  │ ─────────────────────────────► │   CompliGate   │
   │ / dApp   │                                │    Backend     │
   └──────────┘                                └───────┬────────┘
        ▲                                              │
        │                                              │ evaluates KYC, sanctions,
        │                                              │ reserve, jurisdiction, limits
        │                                              ▼
        │  2. Proof Bundle (Ed25519-signed) + bundle_hash
        │ ◄────────────────────────────────────────────┘
        │
        │  3. Submit XRPL Payment with Memo = bundle_hash
        ▼
   ┌──────────────────────────────────────────────────────────┐
   │              XRP Ledger (Testnet)                        │
   │   Payment tx settles, returns tx_hash                    │
   └───────────────────────────┬──────────────────────────────┘
                               │
                               │  4. POST /v1/settle/verify { tx_hash, bundle, signature }
                               ▼
                    ┌────────────────────┐
                    │   CompliGate       │  fetches tx by hash, checks
                    │ verifies on-ledger │  amount / currency / issuer /
                    │ tx vs bundle       │  destination / memo == bundle_hash
                    └─────────┬──────────┘
                              │
                              ▼
                  5. Verification result + Proof artifact
```

Steps 3 and 4 use the **real XRPL testnet** via `XRPL_RPC_URL`. The sanctions check in step 1 is currently served by a **mock provider** unless an HTTP provider is configured (see [Current Status & Limitations](#current-status--limitations)).

---

## Architecture

```mermaid
flowchart TB
    UI[React Frontend] --> API[FastAPI Backend]

    API --> Permit[Permit Service]
    API --> XRPL[XRPL Service]
    API --> Settlement[Settlement Verification Service]
    API --> Proof[Proof Artifact Service]

    Permit --> Policy[Policy Evaluation]
    Policy --> Provider[Compliance Provider Layer]
    Provider --> MockTRM[mock_trm Provider]
    Provider -. future .-> TRM[TRM Labs API]

    Permit --> DB[(PostgreSQL)]
    Proof --> DB
    Settlement --> DB

    XRPL --> Ledger[XRPL Testnet]
    Settlement --> Ledger

    Ledger --> Tx[tx_hash + memo bundle_hash]
    Settlement --> Artifact[Settlement Proof Artifact]
```

- XRPL execution is real testnet
- compliance provider is `mock_trm` in MVP
- TRM integration is pending API access

Key properties:

- **CompliGate does not sit on the settlement path.** Users submit their own XRPL transaction; CompliGate verifies it after the fact.
- **Providers are pluggable and fail-closed.** The default kind is `null`, which denies. Configuration is explicit.
- **The Proof Bundle is the contract.** It is canonical, signed, hashed, time-bound, and independently verifiable using only the public key from `/public-key`.

---

## Current Capabilities

- ✅ Pre-transaction **authorization API** (`/v1/permit`) producing a canonical-JSON, Ed25519-signed Proof Bundle with explicit constraints (action, currency, issuer, amount ceiling) and a hard validity window (`iat` → `exp`, default 5 minutes).
- ✅ **Bundle verification API** (`/v1/verify`) — signature + expiry checks usable by any third party with the public key from `/public-key`.
- ✅ **Post-settlement verification API** (`/v1/settle/verify`) against a real XRPL transaction hash — confirms the settled tx matches the bundle's constraints and that the bundle's `bundle_hash` is present in the XRPL memo.
- ✅ Real **XRPL testnet integration** for transaction lookup and (optional, gated) signing/submission via `XRPL_SIGNING_MODE=seed`. End-to-end testnet roundtrip script included (`backend/scripts/xrpl_testnet_roundtrip.py`).
- ✅ **Pluggable, fail-closed compliance providers** for KYC, sanctions, and reserve / 1:1 backing, with normalized `ProviderResult` evidence persisted in the proof artifact.
- ✅ **HMAC-signed upstream assertions** for KYC and reserve / liquidity attestations, with explicit trusted-issuer / trusted-attestor allowlists.
- ✅ **API key authentication** on all `/v1/*` endpoints (`X-API-Key` or `Authorization: Bearer`), with rotatable, comma-separated key lists.
- ✅ **PostgreSQL persistence** of permits and proof artifacts via SQLAlchemy + Alembic migrations.
- ✅ **Frontend demo** (Vite + React + TypeScript) wiring a permit → settle → verify flow against the running backend.

---

## Current Status and Limitations

CompliGate is at **MVP stage**. This section is intentionally honest and technical about which pieces are real and which are stubs.

**Current MVP includes:**

- Real XRPL testnet execution
- Memo-linked authorization context
- Settlement verification
- PostgreSQL persistence
- Proof artifacts

**Current limitations:**

- Compliance provider is `mock_trm`, not live TRM
- KYC and reserve/liquidity providers are not fully wired
- Settlement verification still depends on persisted backend permit context
- Replay/single-use enforcement is not fully hardened
- Signer model is testnet/demo-oriented
- Not production-ready for regulated environments

> **This repo should be evaluated as an XRPL-integrated compliance authorization prototype, not production financial infrastructure.**

What CompliGate is explicitly **not**:

- Not a broker, broker-dealer, custodian, or transaction intermediary.
- Not an on-ledger enforcement mechanism — XRPL will execute a transaction whether or not CompliGate authorized it. CompliGate provides off-ledger authorization and on-ledger *verification of conformance*.
- Not a substitute for a regulated KYC, sanctions, or proof-of-reserves provider. CompliGate consumes evidence from such providers; it does not produce it.

---

## Quickstart

Prerequisites: Python 3.11+, Node 20+, and a reachable PostgreSQL instance.

```bash
# 1. Backend
cd backend
cp .env.example .env
# At minimum set in .env:
#   DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/compligate
#   API_KEYS=local-dev-key                 # or API_KEY_ENABLED=false
#   XRPL_RPC_URL=https://s.altnet.rippletest.net:51234
#   XRPL_NETWORK=testnet
#   SANCTIONS_PROVIDER=mock_trm            # MVP only — see limitations
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 -m alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

```bash
# 2. Frontend (in a second shell)
cd frontend
cp .env.example .env
npm install
npm run dev
```

```bash
# 3. End-to-end XRPL testnet roundtrip (real network)
cd backend
python3 scripts/xrpl_testnet_roundtrip.py
```

Interactive API docs: <http://localhost:8000/docs>.

For deeper backend setup (Docker, production deployment, Alembic workflow, signing modes), see [`backend/README.md`](backend/README.md).

---

## API Endpoints

All `/v1/*` endpoints are protected by API key authentication when keys are configured (`X-API-Key` header or `Authorization: Bearer <key>`).

| Method | Path                    | Description                                                                                  |
| ------ | ----------------------- | -------------------------------------------------------------------------------------------- |
| `GET`  | `/health`               | Liveness probe. Returns `{"status": "ok"}`. Public.                                          |
| `GET`  | `/public-key`           | Ed25519 public key (base64 + hex) used to verify Proof Bundle signatures. Public.            |
| `POST` | `/v1/permit`            | Run authorization. Returns a signed Proof Bundle with constraints, `iat`/`exp`, `bundle_hash`. |
| `POST` | `/v1/verify`            | Verify a Proof Bundle's signature and expiry without contacting XRPL.                        |
| `POST` | `/v1/settle/verify`     | Post-settlement verification of an XRPL `tx_hash` against a Proof Bundle's constraints.      |
| `GET`  | `/v1/xrpl/health`       | Reports whether the configured XRPL network is reachable.                                    |
| `POST` | `/v1/xrpl/payment`      | Optional, gated XRPL signing/submission. Disabled unless `XRPL_SIGNING_ENABLED=true` and `XRPL_SIGNING_MODE=seed`. Testnet only. |

Example — request a permit and verify it:

```bash
curl -X POST http://localhost:8000/v1/permit \
  -H "X-API-Key: local-dev-key" \
  -H "Content-Type: application/json" \
  -d '{"subject": "rExampleSubjectAddress...", "action": "transfer", "amount": 100.00}'
```

```bash
curl -X POST http://localhost:8000/v1/settle/verify \
  -H "X-API-Key: local-dev-key" \
  -H "Content-Type: application/json" \
  -d '{"tx_hash": "<xrpl-tx-hash>", "bundle": { ... }, "signature": "<base64>"}'
```

---

## Environment Variables

The variables below are the most important for getting CompliGate running. The full list — including every compliance-provider knob, signing mode, and persistence option — is documented in [`backend/.env.example`](backend/.env.example) and [`backend/README.md`](backend/README.md).

### Core / policy

| Variable                       | Description                                                                                              |
| ------------------------------ | -------------------------------------------------------------------------------------------------------- |
| `POLICY_VERSION`               | Policy identifier embedded in every Proof Bundle (e.g. `RLUSD_US_v1`).                                   |
| `JURISDICTION`                 | Jurisdiction code embedded in the bundle (e.g. `US`).                                                    |
| `CURRENCY`, `ISSUER_ADDRESS`   | Currency and issuer bound to the permit (e.g. `RLUSD` + the RLUSD issuer).                               |
| `PERMIT_TTL_SECONDS`           | Permit time-to-live (default `300`).                                                                     |
| `COMPLIGATE_PRIVATE_KEY_B64`   | Base64-encoded Ed25519 seed used to sign Proof Bundles. Required for stable keys; ephemeral in dev.      |
| `CORS_ORIGINS`                 | Comma-separated allowed CORS origins.                                                                    |

### Persistence & auth

| Variable                                      | Description                                                                              |
| --------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `DATABASE_URL`                                | PostgreSQL URL (`postgresql+psycopg://…`). Required outside of narrow local experiments. |
| `API_KEY_ENABLED`, `API_KEYS`, `API_KEY_HEADER_NAME` | API key auth toggle, comma-separated keys, and configurable header name.            |

### XRPL

| Variable                | Description                                                                                                |
| ----------------------- | ---------------------------------------------------------------------------------------------------------- |
| `XRPL_RPC_URL`          | XRPL JSON-RPC URL (default: testnet).                                                                      |
| `XRPL_NETWORK`          | Network identifier embedded in verification metadata (`testnet`, `mainnet`, `devnet`).                     |
| `XRPL_SIGNING_MODE`     | `seed` (dev/staging only), `disabled`, or `external` (HSM placeholder, not implemented).                   |
| `XRPL_SIGNING_ENABLED`  | Master kill switch for signing.                                                                            |
| `XRPL_SIGNER_SEED`      | Seed used by `seed` signing mode. **Testnet only.** Never set to a mainnet seed.                            |
| `XRPL_SIGNER_ADDRESS`   | Optional. If set, the seed must derive to this XRPL address or signing is refused.                         |
| `RLUSD_ISSUER`, `RLUSD_CURRENCY`, `XRPL_REQUIRE_TRUSTLINE`, `XRPL_ENFORCE_RLUSD_ONLY` | RLUSD-specific configuration. |

### Compliance providers (fail-closed by default)

| Variable                       | Description                                                                                              |
| ------------------------------ | -------------------------------------------------------------------------------------------------------- |
| `FAIL_CLOSED_COMPLIANCE`       | When `true` (default), `denied` or `unavailable` provider responses produce a `DENY`. Keep `true` outside of narrow local dev. |
| `KYC_PROVIDER`                 | `null` (default), `static_allow` (dev only), `http`, or `upstream_assertion`.                            |
| `SANCTIONS_PROVIDER`           | `null` (default), `static_allow` (dev only), `http`, `address_screen`, or `mock_trm` (MVP simulation, **not** a real TRM integration). |
| `RESERVE_PROVIDER`             | `null` (default), `static_allow` (dev only), `http`, or `attestation`.                                   |
| `*_PROVIDER_URL`, `*_API_KEY`  | HTTPS endpoint and bearer key for `http`-mode providers.                                                 |
| `KYC_UPSTREAM_ASSERTION_SECRET`, `KYC_UPSTREAM_ASSERTION_TRUSTED_ISSUERS` | HMAC secret and allowlist for trusted-upstream KYC assertions. |
| `RESERVE_ATTESTATION_SECRET`, `RESERVE_ATTESTATION_TRUSTED_ATTESTORS`     | HMAC secret and allowlist for trusted reserve / liquidity attestors. |

---

## Test Plan

Automated:

```bash
# Backend unit + integration tests (PostgreSQL not required — uses test fixtures)
cd backend
source .venv/bin/activate
pytest tests/
```

The suite under `backend/tests/` covers:

- Policy engine and authorization decisions (`test_compliance.py`, `test_provider_compliance.py`)
- Proof Bundle issuance, signature, and expiry (`test_api.py`)
- Each provider type, including HTTP sanctions, KYC upstream assertions, and reserve attestations (`test_http_sanctions_provider.py`, `test_kyc_upstream_assertion.py`, `test_reserve_attestation.py`, `test_providers.py`)
- Settlement verification reason codes and edge cases (`test_settlement_reason_codes.py`, `test_settlement_service.py`)
- XRPL integration paths (`test_xrpl_integration_real.py`)

End-to-end against the **real XRPL testnet** (requires outbound network access to the XRPL testnet faucet + JSON-RPC endpoint):

```bash
cd backend
python3 scripts/xrpl_testnet_roundtrip.py
```

This script submits a real testnet `Payment` carrying a CompliGate `bundle_hash` in a memo, fetches the transaction back, and runs CompliGate's settlement verification against it.

Frontend:

```bash
cd frontend
npm test          # vitest
```

Manual smoke test (after `uvicorn` is running):

1. `curl http://localhost:8000/health` → `{"status": "ok"}`
2. `curl http://localhost:8000/public-key` → returns Ed25519 public key.
3. `POST /v1/permit` → receive Proof Bundle.
4. `POST /v1/verify` → confirm signature + expiry.
5. Submit XRPL testnet payment with `bundle_hash` in memo.
6. `POST /v1/settle/verify` with the resulting `tx_hash` → verification result.

---

## Roadmap

**Now (MVP — this repository)**
- Authorization, Proof Bundle issuance, and post-settlement verification on XRPL testnet
- Pluggable, fail-closed provider abstractions for KYC / sanctions / reserves
- Mock sanctions provider (`mock_trm`) for local development and demos

**Next**
- Real **TRM Labs** sanctions provider (replacing `mock_trm` with a true HTTP integration)
- Real KYC vendor integration behind the existing `KYC_PROVIDER=http` interface
- Real proof-of-reserves / liquidity vendor behind `RESERVE_PROVIDER=http`
- Expanded asset-classification logic (security / commodity / payment token signals)
- Hardened key management: `XRPL_SIGNING_MODE=external` (HSM / custody) implementation
- Production XRPL mainnet support, including stricter trustline and issuer enforcement
- Independent security review and audit of the authorization engine and Proof Bundle format

**Later**
- Multi-chain authorization (same Proof Bundle shape, additional settlement verifiers)
- Optional on-ledger anchoring of `bundle_hash` for long-term tamper-evidence
- Standardization of the Proof Bundle as a portable compliance artifact

---

## Contact

CompliGate is developed by **CompliLedger**.

- Issues & discussion: <https://github.com/Compliledger/CompliGate/issues>
- Security reports: please open a private security advisory via this repository.
- General contact / partnership inquiries: open a GitHub issue and a maintainer will follow up.

License: TBD.
