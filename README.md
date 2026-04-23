CompliGate

Deterministic Compliance Authorization for XRPL

CompliGate is a compliance authorization layer for the XRP Ledger (XRPL) that defines the conditions under which transactions are allowed to execute—and produces verifiable proof that those conditions were met.

⸻

⚖️ Core Principle

CompliGate does not execute transactions.
It defines the conditions under which transactions are valid.

⸻

🚨 Why This Matters

Regulatory frameworks including:
	•	SEC/CFTC Tokenization Framework (Release 33-11412)
	•	GENIUS Act (stablecoin requirements)
	•	CLARITY Act (jurisdiction + AML/KYC)

require:
	•	transaction-level compliance
	•	real-time enforcement
	•	audit-ready evidence

⸻

❌ The Problem

XRPL provides:
	•	trust lines
	•	issuer controls
	•	freeze / clawback

But lacks:
	•	deterministic compliance logic
	•	policy-based activation
	•	verifiable compliance outputs

⸻

✅ The Solution

CompliGate introduces:
	•	Deterministic policy evaluation
	•	Transaction constraints
	•	Cryptographic proof artifacts
	•	XRPL-native integration

⸻

🧩 Architecture
User → CompliGate → XRPL → CompliGate → Proof Artifact
Flow
	1.	Request Permit
	2.	Evaluate Compliance
	3.	Generate Constraints
	4.	Execute Transaction (XRPL)
	5.	Verify Settlement
	6.	Produce Proof

⸻

🔗 XRPL Integration (LIVE)

CompliGate is integrated with XRPL Testnet:

Features
	•	✅ Real XRPL transaction submission
	•	✅ RLUSD issued asset support
	•	✅ Trustline validation
	•	✅ Transaction memo linking (bundle_hash → tx_hash)
	•	✅ Settlement verification using live XRPL data

⸻

Example Flow

1. Request Permit
{
  "subject": "r...",
  "action": "transfer",
  "amount": "100"
}
2. CompliGate Evaluates

Checks:
	•	Asset classification
	•	Jurisdiction (KYC / sanctions via configured providers)
	•	Transaction limits
	•	Reserve attestation via configured provider
	•	Trustline requirement

⸻

3. Constraint Output
This transaction is valid only if:
- trustline exists
- amount < threshold
- asset = compliant
- issuer = approved
4. XRPL Transaction
	•	Payment submitted to XRPL Testnet
	•	RLUSD issued currency
	•	bundle_hash embedded as memo

⸻

5. Settlement Verification

CompliGate validates:
	•	transaction details
	•	asset + issuer
	•	compliance conditions

⸻

6. Proof Artifact
{
  "module": "CompliGate",
  "entity_id": "<tx_hash>",
  "rule_version_used": "v1",
  "decision_result": "SETTLED_COMPLIANT",
  "reason_codes": [],
  "timestamp": 1234567890,
  "bundle_hash": "...",
  "anchor_metadata": {
    "network": "xrpl-testnet",
    "tx_hash": "...",
    "ledger_index": 123456
  }
}
🔐 Compliance Coverage (MVP)

CompliGate currently evaluates:

✔ Asset Classification
	•	stablecoin / RWA (policy-defined)

✔ 1:1 Backing (Provider-Backed)
	•	reserve attestation via configured RESERVE_PROVIDER (fail-closed when unavailable)

✔ Jurisdiction Controls
	•	KYC and sanctions screening via configured KYC_PROVIDER and SANCTIONS_PROVIDER (fail-closed when unavailable)

✔ Transaction Limits
	•	policy thresholds

✔ XRPL Trustlines
	•	enforced at ledger level

Every compliance decision is traceable to real provider evidence (or
explicit denial); the per-check provider id, status and reference are
persisted in the bundle and proof artifact under
``compliance_evidence``.

⸻

⚠️ Important Note

CompliGate is:
	•	NOT a broker
	•	NOT an intermediary
	•	NOT executing trades

It is:

An authorization and verification layer

⸻

🏗️ Deployment Models

🟢 Hosted (Attestation)
	•	CompliGate evaluates + proves
	•	no execution control

🟡 Self-Hosted (Institutional)
	•	deployed inside broker-dealer
	•	institution enforces

🔵 Hybrid
	•	CompliGate signals
	•	institution executes

⸻

🚀 Local Development

Backend
cd backend
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --reload
Frontend
cd frontend
npm install
npm run dev
⚙️ Environment Variables
XRPL_RPC_URL=
XRPL_NETWORK=testnet
XRPL_DEMO_WALLET_SEED=
RLUSD_ISSUER=
RLUSD_CURRENCY=RLUSD
XRPL_REQUIRE_TRUSTLINE=true
🧪 Key Endpoints
Endpoint
Description
/v1/permit
Generate compliance authorization
/v1/verify
Verify signature + expiration
/v1/xrpl/health
XRPL connectivity
/v1/xrpl/trustline/check
Validate trustline
/v1/xrpl/payment
Submit XRPL transaction
/v1/settlement/verify
Verify settlement compliance
🧠 Strategic Positioning

XRPL provides:
	•	execution
	•	settlement

CompliGate provides:
	•	authorization
	•	compliance

⸻

Final Model
Authorization → Execution → Verification → Proof
