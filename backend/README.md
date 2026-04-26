# CompliGate Backend

CompliGate is the transaction-time authorization and constraint verification layer of CompliLedger. It issues time-bound, cryptographically signed permits that determine whether a transaction is authorized, define the constraints under which it may proceed, and specify when the authorization is valid. Each permit is packaged as a Proof Bundle — a canonical JSON document signed with Ed25519 and hashed for on-chain anchoring.

---

## Core Model

### Authorization (Before Settlement)
CompliGate evaluates incoming requests against configured policy before any transaction proceeds.
- Subject identity is bound to the permit at issuance
- Policy version and jurisdiction are embedded in every bundle
- Requests that fail policy evaluation receive an explicit DENY

### Constraints (During Settlement)
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
User → CompliGate Backend → Proof Bundle → User settles tx on XRPL → POST /v1/settle/verify → Post-settlement verification
```

- **XRPL** is the settlement layer. CompliGate does not submit transactions — it operates as an independent verifier.
- Users obtain a permit, independently settle the transaction on XRPL, then submit the XRPL transaction hash back to CompliGate for post-settlement verification.
- CompliGate checks that the settled transaction conforms to the permit constraints (amount, currency, counterparty, action type).

---

## Role Within CompliLedger

CompliGate operates at the point of authorization and post-settlement
verification. It is the **enforcement gate** — it does not itself
perform the underlying compliance work:

- It does not capture identity documents, run identity verification, or
  maintain sanctions / watchlist data.
- It does not generate reserve / proof-of-reserves attestations.
- It does not classify assets.

Instead, CompliGate **consumes structured evidence** from configured
providers and trusted upstream sources, and enforces a fail-closed
policy gate before issuing a signed permit. For each request it
evaluates:

- **KYC** — provider-backed (`KYC_PROVIDER=http`) **or**
  trusted-upstream-backed (`KYC_PROVIDER=upstream_assertion`, an
  HMAC-signed assertion from an institution listed in
  `KYC_UPSTREAM_ASSERTION_TRUSTED_ISSUERS`).
- **Sanctions screening** — provider-backed (`SANCTIONS_PROVIDER=http`
  or `address_screen`).
- **Reserve / liquidity** — provider-backed (`RESERVE_PROVIDER=http`)
  **or** attestor-backed (`RESERVE_PROVIDER=attestation`, an HMAC-signed
  attestation from a custodian / auditor / issuer listed in
  `RESERVE_ATTESTATION_TRUSTED_ATTESTORS`).

When `FAIL_CLOSED_COMPLIANCE=true` (the default) any provider that
returns `denied` **or** `unavailable` causes the request to be denied
with an explicit `*_DENIED` / `*_PROVIDER_UNAVAILABLE` reason code.
Missing provider configuration is treated identically to an unavailable
response. The provider response, including its evidence reference, is
persisted in the proof artifact so every decision is traceable to the
source that produced it. The default provider kind for every check is
`null`, so an unconfigured deployment denies every request rather than
silently approving anything.

The decision returned to the caller is binary — **ALLOW** or **DENY** —
backed by a cryptographic Proof Bundle that records the underlying
provider evidence.

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
- **Post-settlement verification** — after a user independently settles a transaction on XRPL, CompliGate verifies the outcome against the permit constraints

---

## Persistence (PostgreSQL)

CompliGate persists issued permits and proof artifacts in **PostgreSQL**. A reachable PostgreSQL instance is required for any non-trivial deployment, and is strongly recommended for local development to match production behavior.

- Connection is configured via `DATABASE_URL` (SQLAlchemy URL, psycopg driver), e.g.:
  ```
  postgresql+psycopg://<user>:<password>@localhost:5432/compligate
  ```
- Schema is managed by Alembic — see [Database Migrations](#database-migrations-alembic). Migrations are **not** auto-applied on startup; run them explicitly before booting the API.
- `DATABASE_URL` must be set in production. Leaving it unset is only intended for narrow local experimentation and is not a supported runtime configuration.

---

## Database Migrations (Alembic)

Alembic is initialized in `backend/alembic/` and reads `DATABASE_URL` from `app/core/config.py`. Revision scripts live in `backend/alembic/versions/`.

Common commands (run from `backend/` with `DATABASE_URL` exported or present in `.env`):

```bash
# Show the current revision applied to the database
python3 -m alembic current

# Generate a new revision from model changes
python3 -m alembic revision --autogenerate -m "describe change"

# Apply migrations up to the latest revision
python3 -m alembic upgrade head

# Roll back the most recent migration
python3 -m alembic downgrade -1
```

Always run `alembic upgrade head` before starting the API after a fresh checkout, after pulling new code, or as part of any deployment.

---

## Authentication (API Keys)

All `/v1/*` endpoints are protected by API key authentication when keys are configured. `/health` and `/public-key` remain public.

- **Enable/disable**: `API_KEY_ENABLED` (default `true`). When disabled, requests are not authenticated — only appropriate for local development.
- **Header name**: configurable via `API_KEY_HEADER_NAME` (default `X-API-Key`).
- **Configured keys**: `API_KEYS` is the preferred variable (comma-separated). `AUTH_API_KEYS` is a legacy fallback kept for backward compatibility; `API_KEYS` takes precedence when both are set.
- **Supported request formats**:
  - `X-API-Key: <key>` (or whatever header is configured via `API_KEY_HEADER_NAME`)
  - `Authorization: Bearer <key>`
  - `Authorization: <key>` (raw value)
- If no keys are configured, authentication is effectively a no-op. Configure at least one key in any shared or production environment.

Example:

```bash
curl -H "X-API-Key: $COMPLIGATE_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"subject":"r...","action":"transfer","amount":1000.00}' \
     https://your-host/v1/permit
```

---

## XRPL Signing

The `/v1/xrpl/payment` endpoint can sign and submit XRPL transactions on behalf of the operator. Signing is gated by both a master kill switch and an explicit signing **mode**.

### Signing modes (`XRPL_SIGNING_MODE`)

| Mode | Behavior | Intended use |
|------|----------|--------------|
| `seed` | Local seed-based signing using `XRPL_SIGNER_SEED` (or legacy `XRPL_SIGNING_SEED` as fallback). Use a testnet or devnet seed only. | Development and staging only. Do **not** use a mainnet seed here. |
| `disabled` | Signing is turned off. The payment endpoint returns a structured error. | Environments where CompliGate must never sign (e.g., authorization-only deployments). |
| `external` | Placeholder for a future HSM / custody signer integration. Not implemented yet — endpoint returns a structured "not implemented" error. | Reserved for production custody integration. |

### Kill switch

`XRPL_SIGNING_ENABLED` (default `true`) is a master switch. When set to `false`, the payment endpoint returns a structured error regardless of the configured `XRPL_SIGNING_MODE`. Use this to disable signing without changing mode configuration.

### Signer binding

`XRPL_SIGNER_ADDRESS` is optional. When set, the seed must derive to this XRPL classic address; if it does not, signing is refused. This guards against misconfiguration where the wrong seed is loaded into an environment.

---

## Environment Variables

### Core / policy

| Variable | Description |
|----------|-------------|
| `POLICY_VERSION` | Policy identifier embedded in every Proof Bundle (e.g., `RLUSD_US_v1`). |
| `JURISDICTION` | Jurisdiction code included in the bundle (e.g., `US`). |
| `CURRENCY` | Currency code bound to the permit (e.g., `RLUSD`). |
| `ISSUER_ADDRESS` | Issuer address bound to the permit. |
| `COMPLIGATE_PRIVATE_KEY_B64` | Base64-encoded Ed25519 seed (32 bytes) used to sign Proof Bundles. **Required in production.** If blank, an ephemeral key is generated on startup (dev only). |
| `CORS_ORIGINS` | Comma-separated list of allowed CORS origins. |
| `PERMIT_TTL_SECONDS` | Permit time-to-live in seconds (default: `300`). |
| `PERMIT_CONTEXT_CACHE_MAX_ITEMS` | Max in-memory recent permit contexts retained (default: `1000`). |

### Persistence

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection URL (e.g., `postgresql+psycopg://user:pass@host:5432/compligate`). Required in production. |

### API key auth

| Variable | Description |
|----------|-------------|
| `API_KEY_ENABLED` | Enables API key auth (default: `true`). Set to `false` only for local development. |
| `API_KEY_HEADER_NAME` | Header used for API key auth (default: `X-API-Key`). |
| `API_KEYS` | Comma-separated valid API keys. Preferred variable. |
| `AUTH_API_KEYS` | Legacy fallback for API keys; `API_KEYS` takes precedence when both are set. |

### Compliance providers

CompliGate's authorization gate is provider-driven and fail-closed. The
default kind for every check is `null` — an unconfigured deployment
denies every request. Configure each check explicitly for any
non-trivial environment.

| Variable | Description |
|----------|-------------|
| `FAIL_CLOSED_COMPLIANCE` | When `true` (default), any `denied` or `unavailable` provider response causes the request to be denied. Set to `false` only for narrow local development. |
| `KYC_PROVIDER` | One of `null`, `static_allow`, `http`, `upstream_assertion`. `static_allow` is **not** suitable for production. |
| `KYC_PROVIDER_URL`, `KYC_API_KEY` (or legacy `KYC_PROVIDER_API_KEY`) | HTTPS endpoint and bearer key used when `KYC_PROVIDER=http`. |
| `KYC_UPSTREAM_ASSERTION_SECRET` | HMAC shared secret used to validate trusted-upstream KYC assertions when `KYC_PROVIDER=upstream_assertion`. |
| `KYC_UPSTREAM_ASSERTION_TRUSTED_ISSUERS` | Comma-separated allowlist of upstream institutional issuer ids whose KYC assertions are accepted. |
| `SANCTIONS_PROVIDER` | One of `null`, `static_allow`, `http`, `address_screen`. |
| `SANCTIONS_PROVIDER_URL`, `SANCTIONS_API_KEY` (or legacy `SANCTIONS_PROVIDER_API_KEY`) | HTTPS endpoint and bearer key used when `SANCTIONS_PROVIDER=http`. |
| `RESERVE_PROVIDER` | One of `null`, `static_allow`, `http`, `attestation`. |
| `RESERVE_PROVIDER_URL`, `RESERVE_API_KEY` (or legacy `RESERVE_PROVIDER_API_KEY`) | HTTPS endpoint and bearer key used when `RESERVE_PROVIDER=http`. |
| `RESERVE_ATTESTATION_SECRET` | HMAC shared secret used to validate trusted reserve / liquidity attestations when `RESERVE_PROVIDER=attestation`. |
| `RESERVE_ATTESTATION_TRUSTED_ATTESTORS` | Comma-separated allowlist of attestor ids (custodian / auditor / issuer) whose reserve attestations are accepted. |

### XRPL network & RLUSD

| Variable | Description |
|----------|-------------|
| `XRPL_RPC_URL` | XRPL JSON-RPC URL used for settlement verification and submission (default: XRPL Testnet). |
| `XRPL_NETWORK` | XRPL network identifier used in verification metadata (e.g., `xrpl_testnet`, `mainnet`). |
| `XRPL_DEMO_WALLET_SEED` | Seed for the demo XRPL wallet — **testnet only**. Never set to a mainnet seed. |
| `RLUSD_ISSUER` | RLUSD issuer address on XRPL. Leave blank to skip issuer validation. |
| `RLUSD_CURRENCY` | RLUSD currency code (default: `RLUSD`). |
| `XRPL_REQUIRE_TRUSTLINE` | Require trustline for RLUSD before settlement (default: `true`). |
| `XRPL_ENFORCE_RLUSD_ONLY` | Reject non-RLUSD payments (default: `false`). |

### XRPL signing

| Variable | Description |
|----------|-------------|
| `XRPL_SIGNING_MODE` | One of `seed`, `disabled`, `external` (default: `seed`). See [XRPL Signing](#xrpl-signing). |
| `XRPL_SIGNING_ENABLED` | Master kill switch for signing (default: `true`). |
| `XRPL_SIGNER_ADDRESS` | Optional. Expected XRPL classic address of the signer; seed must derive to this address. |
| `XRPL_SIGNER_SEED` | Seed used by the `seed` signing mode. Preferred over `XRPL_SIGNING_SEED`. |
| `XRPL_SIGNING_SEED` | Legacy signing seed kept for backward compatibility; used as a fallback when `XRPL_SIGNER_SEED` is not set. |

Copy `.env.example` to `.env` and fill in values before running locally.

---

## Running Locally

Local startup assumes a reachable PostgreSQL instance. The recommended flow:

1. **Provision PostgreSQL** (locally or via Docker) and create a database, e.g.:
   ```bash
   createdb compligate
   ```
2. **Configure environment**:
   ```bash
   cd backend
   cp .env.example .env
   # Edit .env and set at minimum:
   #   DATABASE_URL=postgresql+psycopg://<user>:<pass>@localhost:5432/compligate
   #   API_KEYS=<a-local-dev-key>            # or set API_KEY_ENABLED=false
   #   XRPL_SIGNING_MODE=seed | disabled
   #   XRPL_SIGNER_SEED=<testnet-seed>       # only if XRPL_SIGNING_MODE=seed
   ```
3. **Install dependencies**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
4. **Apply database migrations**:
   ```bash
   python3 -m alembic upgrade head
   ```
5. **Start the API**:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```

The API will be available at `http://localhost:8000`. Interactive docs are at `http://localhost:8000/docs`.

---

## Running in Production

Production deployments must run against a managed PostgreSQL instance with persistent Ed25519 keys, real API keys, and an explicit XRPL signing configuration.

1. **Provision PostgreSQL** and obtain a connection string. Set `DATABASE_URL` in the deployment environment.
2. **Configure required environment variables**:
   - `COMPLIGATE_PRIVATE_KEY_B64` — a stable base64-encoded Ed25519 seed (do not rely on the ephemeral dev-mode key).
   - `API_KEY_ENABLED=true` and `API_KEYS=<comma-separated production keys>`.
   - `DATABASE_URL` — production PostgreSQL URL.
   - `XRPL_RPC_URL`, `XRPL_NETWORK` — production XRPL endpoint and network identifier.
   - `XRPL_SIGNING_MODE` — set explicitly:
     - `disabled` for authorization-only deployments,
     - `seed` for staging-style deployments (never with a mainnet seed),
     - `external` once HSM/custody integration is available.
   - `XRPL_SIGNING_ENABLED` — leave `true` only if signing is intended; otherwise `false` as a defense-in-depth kill switch.
   - `XRPL_SIGNER_ADDRESS` — set to bind the configured seed to a specific XRPL address.
   - `POLICY_VERSION`, `JURISDICTION`, `CURRENCY`, `ISSUER_ADDRESS`, `RLUSD_ISSUER` — set to production values.
   - `CORS_ORIGINS` — restricted to the production frontend origins.
3. **Build and ship the container**:
   ```bash
   docker build -t compligate-backend .
   ```
4. **Run database migrations against the production database** before (or as part of) each release:
   ```bash
   python3 -m alembic upgrade head
   ```
   This step must complete successfully before the API process starts.
5. **Start the API** with a production-grade ASGI command (the container `CMD` and `railway.toml` `startCommand` use):
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
   ```
   Run behind a reverse proxy / load balancer that terminates TLS and forwards the configured API key header.

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

The container does not run Alembic automatically. Apply migrations against the target database before starting the container, or run `python3 -m alembic upgrade head` as a one-off command in the same image.

---

## Roadmap

**Current phase**
- XRPL integration: post-settlement verification for RLUSD payments and trustline operations
- Frontend settlement verification flow

**Next phase**
- Production XRPL mainnet support
- Extended RLUSD compliance controls

---

CompliGate enforces policy at authorization and produces cryptographic proof of compliance.
