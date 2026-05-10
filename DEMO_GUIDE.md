# CompliGate Demo Mode Guide

This document explains how to run CompliGate in **demo mode**, where the compliance
providers (KYC, sanctions, reserve/liquidity) are replaced by a deterministic
keyword-driven mock. No real third-party integrations are required.

---

## Enabling demo mode

Set these three environment variables on the deployment (Railway, `.env`, etc.):

```
KYC_PROVIDER=demo
SANCTIONS_PROVIDER=demo
RESERVE_PROVIDER=demo
FAIL_CLOSED_COMPLIANCE=true
```

All other variables stay the same. The backend does not need to be rebuilt —
restart the service after changing the vars.

---

## How the demo provider works

The provider inspects the **subject address** (XRPL wallet) sent in the permit
request. If none of the trigger keywords below are present, every check passes
and a permit is issued. Embed a keyword in the address to force a specific
outcome.

Keyword matching is **case-insensitive** and looks for the string anywhere
inside the address.

### Trigger keywords

| Keyword in subject address | Provider affected | Outcome |
|---|---|---|
| *(none — any normal address)* | all | ✅ all pass → `PERMIT` issued |
| `KYC_DENY` | KYC | ❌ KYC denied → `reason_codes: ["KYC_DENIED"]` |
| `SANCTIONED` | Sanctions | ❌ Sanctions hit → `reason_codes: ["SANCTIONS_HIT"]` |
| `RESERVE_FAIL` | Reserve | ❌ Reserve not verified → `reason_codes: ["RESERVE_STATUS_NOT_VERIFIED"]` |
| `LIQUIDITY_FAIL` | Reserve | ❌ Liquidity not verified → `reason_codes: ["LIQUIDITY_STATUS_NOT_VERIFIED"]` |
| `REVIEW` | all | ⚠️ Provider unavailable → deny under `FAIL_CLOSED_COMPLIANCE` |
| `UNAVAILABLE` | all | ⚠️ Provider unavailable → deny under `FAIL_CLOSED_COMPLIANCE` |

> **Subject length rule:** The backend validates that every subject is 25–35
> characters long (standard XRPL address range). Demo addresses must respect
> this constraint.

---

## Ready-to-use demo addresses

Copy these directly into API requests or the test script.

```
# All checks pass — permit issued
DEMO_PASS_WALLET     = rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh    (35 chars)

# KYC denied
DEMO_KYC_DENY        = rKYC_DENYxd82kLm9Pq7Zr45w             (25 chars)

# Sanctions hit
DEMO_SANCTIONED      = rSANCTIONEDxkd82Lm9P7Zr4w             (25 chars)

# Reserve backing not verified (liquidity passes)
DEMO_RESERVE_FAIL    = rRESERVE_FAILxk82Lm9P7Zr4             (25 chars)

# Liquidity not verified (reserve backing passes)
DEMO_LIQUIDITY_FAIL  = rLIQUIDITY_FAILxd82Lm9P7Z             (25 chars)

# All providers return unavailable → fail-closed → deny
DEMO_UNAVAILABLE     = rUNAVAILABLExkd82Lm9P7Zr4             (25 chars)
```

---

## Example API calls

### Successful permit (all checks pass)

```bash
curl -s -X POST https://compligate-backend-production.up.railway.app/v1/permit \
  -H "X-API-Key: <your-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
    "action": "transfer",
    "amount": 500
  }'
```

Expected `reason_codes` subset: `["KYC_VERIFIED", "SANCTIONS_PASSED", "RESERVE_BACKED"]`

### KYC denial

```bash
curl -s -X POST https://compligate-backend-production.up.railway.app/v1/permit \
  -H "X-API-Key: <your-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "rKYC_DENYxd82kLm9Pq7Zr45w",
    "action": "transfer",
    "amount": 500
  }'
```

Expected `reason_codes` subset: `["KYC_DENIED"]`

### Sanctions hit

```bash
curl -s -X POST https://compligate-backend-production.up.railway.app/v1/permit \
  -H "X-API-Key: <your-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "rSANCTIONEDxkd82Lm9P7Zr4w",
    "action": "transfer",
    "amount": 500
  }'
```

Expected `reason_codes` subset: `["SANCTIONS_HIT"]`

---

## What is recorded in the proof artifact?

The provider id in every proof artifact is always `demo:<check>` (e.g.
`demo:kyc`, `demo:sanctions`, `demo:reserve`). This makes it immediately
visible in any audit log that no real third-party check was performed.

The demo provider kind is listed in `NON_PRODUCTION_PROVIDER_KINDS` inside
`backend/app/services/compliance/providers.py` — the same list that contains
`static_allow` and `null` — so production readiness checks can detect and flag
a demo deployment before it touches real funds.

---

## Running the automated test suite against the demo deployment

```bash
# Point at the live Railway URL with your API key
BASE_URL=https://compligate-backend-production.up.railway.app \
  API_KEY=<your-key> \
  node test-live.js
```

Section 10 of the test script (`Demo mode — keyword triggers`) exercises all
six demo scenarios above and verifies the expected `reason_codes` for each.
