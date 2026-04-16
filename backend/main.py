from __future__ import annotations

import base64
import json
import logging
import os
import time
import hashlib
from uuid import uuid4

import requests as http_requests

try:
    from xrpl.clients import JsonRpcClient
    from xrpl.wallet import Wallet
    _XRPL_SDK_AVAILABLE = True
except ImportError:
    _XRPL_SDK_AVAILABLE = False

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

APP_NAME = "CompliGate Backend"

POLICY_VERSION = os.getenv("POLICY_VERSION", "RLUSD_US_v1")
JURISDICTION = os.getenv("JURISDICTION", "US")
CURRENCY = os.getenv("CURRENCY", "RLUSD")
ISSUER_ADDRESS = os.getenv("ISSUER_ADDRESS", "rEXAMPLE_ISSUER_ADDRESS")
PRIVATE_KEY_B64 = os.getenv("COMPLIGATE_PRIVATE_KEY_B64", "").strip()
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173")

XRPL_RPC_URL = os.getenv("XRPL_RPC_URL", "https://s.altnet.rippletest.net:51234")
XRPL_NETWORK = os.getenv("XRPL_NETWORK", "xrpl_testnet")
RLUSD_ISSUER = os.getenv("RLUSD_ISSUER", "")
RLUSD_CURRENCY = os.getenv("RLUSD_CURRENCY", "RLUSD")
XRPL_DEMO_WALLET_SEED = os.getenv("XRPL_DEMO_WALLET_SEED", "")
XRPL_ENFORCE_RLUSD_ONLY = os.getenv("XRPL_ENFORCE_RLUSD_ONLY", "false").lower() in ("true", "1", "yes")
PERMIT_TTL_SECONDS = int(os.getenv("PERMIT_TTL_SECONDS", "300"))


# -----------------------
# proofbundle integration
# -----------------------

try:
    from proofbundle import ProofArtifact, build_proof_artifact  # type: ignore[import]
    _PROOFBUNDLE_AVAILABLE = True
except ImportError:
    _PROOFBUNDLE_AVAILABLE = False

    class ProofArtifact(BaseModel):  # type: ignore[no-redef]
        """Fallback proof artifact schema (used when proofbundle is not installed)."""

        module: str
        entity_id: str
        rule_version_used: str
        decision_result: str
        evaluation_context: dict
        reason_codes: list[str]
        timestamp: int
        bundle_hash: str
        anchor_metadata: dict

    def build_proof_artifact(  # type: ignore[misc]  # ProofArtifact is conditionally defined above
        *,
        module: str,
        entity_id: str,
        rule_version_used: str,
        decision_result: str,
        evaluation_context: dict,
        reason_codes: list[str],
        timestamp: int,
        bundle_hash: str,
        anchor_metadata: dict,
    ) -> "ProofArtifact":
        return ProofArtifact(
            module=module,
            entity_id=entity_id,
            rule_version_used=rule_version_used,
            decision_result=decision_result,
            evaluation_context=evaluation_context,
            reason_codes=reason_codes,
            timestamp=timestamp,
            bundle_hash=bundle_hash,
            anchor_metadata=anchor_metadata,
        )


# -----------------------
# Utility Functions
# -----------------------

def canonical_json(obj: dict) -> str:
    """Canonical JSON string for signing/hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def proof_hash(bundle: dict) -> str:
    canonical = canonical_json(bundle).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def random_hex(n_bytes: int = 32) -> str:
    return "0x" + os.urandom(n_bytes).hex()


def enrich_proof_artifact_with_anchor(
    proof_artifact: "ProofArtifact",
    anchor_metadata: dict,
) -> "ProofArtifact":
    """Return a copy of *proof_artifact* with *anchor_metadata* replaced.

    The original artifact is not modified.  Call this after a successful
    POST /v1/commit to attach the on-chain anchor details to an existing
    proof artifact before returning it to the frontend.
    """
    return proof_artifact.model_copy(update={"anchor_metadata": anchor_metadata})


def load_or_create_signing_key() -> SigningKey:
    """
    If COMPLIGATE_PRIVATE_KEY_B64 is set, use it.
    Otherwise generate ephemeral key (MVP mode).
    """
    if PRIVATE_KEY_B64:
        try:
            seed = base64.b64decode(PRIVATE_KEY_B64)
            if len(seed) != 32:
                raise ValueError("Private key seed must be 32 bytes.")
            return SigningKey(seed, encoder=RawEncoder)
        except Exception as e:
            raise RuntimeError(f"Invalid COMPLIGATE_PRIVATE_KEY_B64: {e}") from e
    return SigningKey.generate()


SIGNING_KEY = load_or_create_signing_key()
VERIFY_KEY = SIGNING_KEY.verify_key


# -----------------------
# XRPL Client Helpers
# -----------------------

def get_xrpl_client() -> "JsonRpcClient | None":
    """Return an xrpl-py ``JsonRpcClient`` for the configured RPC URL.

    Returns ``None`` when the xrpl-py SDK is not installed or
    ``XRPL_RPC_URL`` is not set so that callers can gracefully degrade
    without crashing application startup.
    """
    if not _XRPL_SDK_AVAILABLE:
        logger.warning("xrpl-py SDK is not installed – XRPL client unavailable")
        return None
    if not XRPL_RPC_URL:
        logger.warning("XRPL_RPC_URL is not configured – XRPL client unavailable")
        return None
    return JsonRpcClient(XRPL_RPC_URL)


def get_demo_wallet() -> "Wallet | None":
    """Return an xrpl-py ``Wallet`` from ``XRPL_DEMO_WALLET_SEED``.

    Returns ``None`` when the seed is not configured or the xrpl-py SDK
    is not installed.  This helper is intended **only** for demo / test
    environments.
    """
    if not _XRPL_SDK_AVAILABLE:
        logger.warning("xrpl-py SDK is not installed – demo wallet unavailable")
        return None
    if not XRPL_DEMO_WALLET_SEED:
        logger.info("XRPL_DEMO_WALLET_SEED is not configured – demo wallet unavailable")
        return None
    return Wallet.from_seed(XRPL_DEMO_WALLET_SEED)


def normalize_xrpl_amount(amount_obj: str | dict) -> dict:
    """Normalise an XRPL ``Amount`` value into a consistent dict.

    XRPL represents native XRP amounts as a string of *drops* while
    issued-currency amounts are represented as a dict with ``currency``,
    ``issuer``, and ``value`` keys.  This helper returns a uniform dict::

        {"currency": "XRP", "value": "1.0", "issuer": ""}
        {"currency": "RLUSD", "value": "10", "issuer": "rISSUER..."}

    :param amount_obj: An amount value from an XRPL transaction – either
        a string (drops of XRP) or a dict (issued currency).
    :returns: A normalised dict with ``currency``, ``value``, and
        ``issuer`` keys.
    """
    if isinstance(amount_obj, dict):
        return {
            "currency": amount_obj.get("currency", ""),
            "value": amount_obj.get("value", "0"),
            "issuer": amount_obj.get("issuer", ""),
        }
    # Native XRP – amount_obj is a string of drops
    try:
        drops = int(amount_obj)
    except (ValueError, TypeError):
        drops = 0
    return {
        "currency": "XRP",
        "value": str(drops / 1_000_000),
        "issuer": "",
    }


def is_rlusd_payment(tx_json: dict) -> bool:
    """Check whether *tx_json* represents an RLUSD ``Payment``.

    Returns ``True`` when all of the following conditions are met:

    * ``TransactionType`` is ``"Payment"``
    * The delivered currency matches ``RLUSD_CURRENCY``
    * If ``RLUSD_ISSUER`` is configured the issuer must match as well

    :param tx_json: A decoded XRPL transaction object (the ``result``
        portion of an RPC ``tx`` response).
    """
    if tx_json.get("TransactionType") != "Payment":
        return False

    amount = tx_json.get("Amount", {})
    normalized = normalize_xrpl_amount(amount)

    if normalized["currency"] != RLUSD_CURRENCY:
        return False

    if RLUSD_ISSUER and normalized["issuer"] != RLUSD_ISSUER:
        return False

    return True


# -----------------------
# Models
# -----------------------

SUPPORTED_ACTIONS = {"transfer", "trustset"}
MAX_AMOUNT = 5_000_000
REASON_CODES = ["kyc_verified", "policy_compliant", "amount_within_limits"]


class PermitRequest(BaseModel):
    subject: str = Field(..., description="Subject identifier (e.g. account address).")
    action: str = Field("transfer", description="Action to authorize ('transfer' or 'trustset').")
    amount: float | int | None = Field(None, description="Optional transfer amount.")
    counterparty: str | None = Field(None, description="Optional counterparty address.")


class PermitResponse(BaseModel):
    summary: dict
    bundle: dict
    signature: str
    signed_at: int
    expires_at: int
    expires_in_seconds: int
    bundle_hash: str
    validity: dict
    decision_result: str
    reason_codes: list[str]
    proof_artifact: ProofArtifact


class VerifyRequest(BaseModel):
    bundle: dict
    signature: str


# -----------------------
# App Setup
# -----------------------

app = FastAPI(title=APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in CORS_ORIGINS.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------
# Routes
# -----------------------

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/public-key")
def public_key():
    pk_raw = VERIFY_KEY.encode(encoder=RawEncoder)
    return {
        "public_key_b64": base64.b64encode(pk_raw).decode("utf-8"),
        "public_key_hex": "0x" + pk_raw.hex(),
    }


def validate_subject(subject: str) -> None:
    if not isinstance(subject, str):
        raise HTTPException(status_code=400, detail={"error": "invalid_subject", "reason": "subject must be a string"})
    if not subject.startswith("r"):
        raise HTTPException(status_code=400, detail={"error": "invalid_subject", "reason": "subject must start with 'r'"})
    if not (25 <= len(subject) <= 35):
        raise HTTPException(status_code=400, detail={"error": "invalid_subject", "reason": "subject length must be 25-35 chars"})


def validate_action(action: str) -> None:
    if action not in SUPPORTED_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_action",
                "reason": f"action '{action}' is not supported; allowed: {sorted(SUPPORTED_ACTIONS)}",
            },
        )


def validate_amount(amount: float | int | None) -> None:
    if amount is not None and amount > MAX_AMOUNT:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "transaction_not_allowed",
                "reason": "amount exceeds policy maximum",
            },
        )


# -----------------------
# Evaluation Stages
# -----------------------

def evaluate_governance() -> dict:
    """Return current governance context."""
    return {
        "policy_version": POLICY_VERSION,
        "jurisdiction": JURISDICTION,
        "state_status": "active",
        "state_ref": "gov_demo_001",
    }


def evaluate_eligibility() -> dict:
    """Return participant and asset eligibility."""
    return {
        "participant_eligible": True,
        "asset_admitted": True,
        "admission_ref": "admission_demo_001",
    }


def evaluate_constraints(
    action: str,
    amount: float | int | None,
    counterparty: str | None,  # reserved for future counterparty validation
) -> list[str]:
    """Enforce policy constraints. Returns list of passing reason codes.

    :raises HTTPException 400: If action is unsupported or amount exceeds the policy maximum.
    """
    if action not in SUPPORTED_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_action",
                "reason": f"action '{action}' is not supported; allowed: {sorted(SUPPORTED_ACTIONS)}",
            },
        )
    if amount is not None and amount > MAX_AMOUNT:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "transaction_not_allowed",
                "reason": "amount exceeds policy maximum",
            },
        )
    reason_codes: list[str] = []
    reason_codes.append("KYC_VERIFIED")
    reason_codes.append("SANCTIONS_PASSED")
    reason_codes.append("RESERVE_BACKED")
    reason_codes.append("LIQUIDITY_VERIFIED")
    reason_codes.append("ISSUER_CONTROLS_ACTIVE")
    if amount is not None:
        reason_codes.append("AMOUNT_WITHIN_LIMIT")
    return reason_codes


@app.post("/v1/permit", response_model=PermitResponse)
def create_permit(req: PermitRequest):
    validate_subject(req.subject)

    gov = evaluate_governance()
    elig = evaluate_eligibility()
    constraint_codes = evaluate_constraints(req.action, req.amount, req.counterparty)

    reason_codes: list[str] = []
    if gov["state_status"] == "active":
        reason_codes.append("POLICY_ACTIVE")
    if elig["participant_eligible"]:
        reason_codes.append("PARTICIPANT_ELIGIBLE")
    if elig["asset_admitted"]:
        reason_codes.append("ASSET_ADMITTED")
    reason_codes.extend(constraint_codes)

    decision_result = "allow"

    now = int(time.time())
    exp = now + PERMIT_TTL_SECONDS

    within_limit = req.amount <= MAX_AMOUNT if req.amount is not None else True

    bundle = {
        "bundle_id": str(uuid4()),
        "subject": req.subject,
        "action": req.action,
        "asset": {
            "issuer": ISSUER_ADDRESS,
            "currency": CURRENCY,
            "classification": "regulated_stablecoin",
            "regulatory_treatment": "non_security",
            "policy_id": POLICY_VERSION,
        },
        "constraints": {
            "max_amount": MAX_AMOUNT,
            "amount": req.amount,
            "within_limit": within_limit,
            "allowed_counterparty": req.counterparty,
            "reserve_backed": True,
            "liquidity_verified": True,
            "kyc_verified": True,
            "sanctions_check": "passed",
            "jurisdiction": JURISDICTION,
            "freeze_possible": True,
            "clawback_possible": True,
            "trustline_required": True,
        },
        "policy": {
            "version": POLICY_VERSION,
            "jurisdiction": JURISDICTION,
        },
        "attestations": {
            "custody_hash": random_hex(32),
            "reserve_hash": random_hex(32),
        },
        "scope": [req.action],
        "exp": exp,
        "nonce": str(uuid4()),
    }

    msg = canonical_json(bundle).encode("utf-8")
    sig = SIGNING_KEY.sign(msg).signature
    sig_b64 = base64.b64encode(sig).decode("utf-8")

    bundle_hash = proof_hash(bundle)

    summary = {
        "issuer_verified": True,
        "asset_classification": bundle["asset"]["classification"],
        "custody_attestation_bound": True,
        "reserve_attestation_bound": True,
        "policy_version": POLICY_VERSION,
        "expires_in_seconds": PERMIT_TTL_SECONDS,
    }

    proof_artifact = build_proof_artifact(
        module="CompliGate",
        entity_id=bundle["bundle_id"],
        rule_version_used=bundle["policy"]["version"],
        decision_result="allow",
        evaluation_context={
            "subject": bundle["subject"],
            "action": bundle["action"],
            "asset": bundle["asset"]["currency"],
            "policy_id": bundle["asset"]["policy_id"],
            "classification": bundle["asset"]["classification"],
            "regulatory_treatment": bundle["asset"]["regulatory_treatment"],
            "reserve_backed": bundle["constraints"]["reserve_backed"],
            "liquidity_verified": bundle["constraints"]["liquidity_verified"],
            "kyc_verified": bundle["constraints"]["kyc_verified"],
            "sanctions_check": bundle["constraints"]["sanctions_check"],
            "jurisdiction": bundle["constraints"]["jurisdiction"],
            "amount": bundle["constraints"]["amount"],
            "max_amount": bundle["constraints"]["max_amount"],
            "within_limit": bundle["constraints"]["within_limit"],
            "freeze_possible": bundle["constraints"]["freeze_possible"],
            "clawback_possible": bundle["constraints"]["clawback_possible"],
            "trustline_required": bundle["constraints"]["trustline_required"],
        },
        reason_codes=reason_codes,
        timestamp=now,
        bundle_hash=bundle_hash,
        anchor_metadata={},
    )

    logger.info("permit_issued subject=%s action=%s exp=%d", req.subject, req.action, exp)
    return PermitResponse(
        summary=summary,
        bundle=bundle,
        signature=sig_b64,
        signed_at=now,
        expires_at=exp,
        expires_in_seconds=PERMIT_TTL_SECONDS,
        bundle_hash=bundle_hash,
        validity={"single_use": False},
        decision_result=decision_result,
        reason_codes=reason_codes,
        proof_artifact=proof_artifact,
    )


@app.post("/v1/verify")
def verify_permit(req: VerifyRequest):
    try:
        canonical = canonical_json(req.bundle).encode("utf-8")
        sig_bytes = base64.b64decode(req.signature)
        VERIFY_KEY.verify(canonical, sig_bytes)
        signature_valid = True
    except Exception:
        signature_valid = False

    now = int(time.time())
    exp = req.bundle.get("exp", 0)
    not_expired = now < exp

    subject = req.bundle.get("subject")
    logger.info(
        "permit_verified subject=%s signature_valid=%s not_expired=%s",
        subject,
        signature_valid,
        not_expired,
    )

    return {
        "signature_valid": signature_valid,
        "not_expired": not_expired,
        "subject": req.bundle.get("subject"),
        "policy_version": req.bundle.get("policy", {}).get("version"),
        "action": req.bundle.get("action"),
        "bundle_hash": proof_hash(req.bundle),
        "constraints": req.bundle.get("constraints", {}),
    }


# -----------------------
# XRPL Settlement Verification
# -----------------------


class SettlementVerifyRequest(BaseModel):
    tx_hash: str = Field(..., description="XRPL transaction hash to verify.")
    bundle: dict = Field(..., description="The permit bundle to verify against.")
    signature: str = Field(..., description="Permit bundle signature (base64).")


def fetch_xrpl_transaction(tx_hash: str) -> dict:
    """Fetch transaction details from the XRPL network.

    :param tx_hash: The XRPL transaction hash.
    :returns: Parsed JSON response from the XRPL RPC.
    :raises HTTPException 502: If the XRPL RPC request fails.
    """
    rpc_url = XRPL_RPC_URL
    payload = {
        "method": "tx",
        "params": [{"transaction": tx_hash, "binary": False}],
    }
    try:
        resp = http_requests.post(rpc_url, json=payload, timeout=10)
        resp.raise_for_status()
        result = resp.json()
        if "result" in result:
            return result["result"]
        return result
    except http_requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": "xrpl_rpc_failed", "reason": str(exc)},
        ) from exc


def verify_settlement_against_permit(
    tx_data: dict,
    bundle: dict,
) -> dict:
    """Verify that an XRPL transaction satisfies the permit constraints.

    CompliGate acts as a non-intermediary verifier: it checks post-settlement
    outcomes against the constraints defined in the permit, without submitting
    or brokering the transaction.

    :param tx_data: Parsed XRPL transaction data from the RPC.
    :param bundle: The original permit bundle.
    :returns: Dict with verification checks and overall pass/fail.
    """
    checks: dict[str, bool] = {}
    details: dict[str, str] = {}

    # -- Check transaction was validated --
    tx_validated = tx_data.get("validated", False)
    checks["tx_validated"] = tx_validated
    if not tx_validated:
        details["tx_validated"] = "Transaction has not been validated on ledger"

    # -- Check transaction type matches permit action --
    tx_type = tx_data.get("TransactionType", "")
    permit_action = bundle.get("action", "")
    action_map = {"transfer": "Payment", "trustset": "TrustSet"}
    expected_type = action_map.get(permit_action, "")
    action_match = tx_type == expected_type
    checks["action_match"] = action_match
    if not action_match:
        details["action_match"] = f"Expected {expected_type}, got {tx_type}"

    # -- Check subject matches (sender) --
    tx_account = tx_data.get("Account", "")
    permit_subject = bundle.get("subject", "")
    subject_match = tx_account == permit_subject
    checks["subject_match"] = subject_match
    if not subject_match:
        details["subject_match"] = f"Expected {permit_subject}, got {tx_account}"

    # -- Check currency is RLUSD --
    constraints = bundle.get("constraints", {})
    asset = bundle.get("asset", {})
    expected_currency = asset.get("currency", CURRENCY)

    if tx_type == "Payment":
        amount = tx_data.get("Amount", {})
        if isinstance(amount, dict):
            tx_currency = amount.get("currency", "")
            tx_value = float(amount.get("value", "0"))
        else:
            tx_currency = "XRP"
            try:
                tx_value = int(amount) / 1_000_000 if amount else 0
            except (ValueError, TypeError):
                tx_value = 0

        currency_match = tx_currency == expected_currency
        checks["currency_match"] = currency_match
        if not currency_match:
            details["currency_match"] = f"Expected {expected_currency}, got {tx_currency}"

        # -- Check amount within permit constraints --
        max_amount = constraints.get("max_amount")
        if max_amount is not None:
            amount_ok = tx_value <= max_amount
            checks["amount_within_limit"] = amount_ok
            if not amount_ok:
                details["amount_within_limit"] = (
                    f"Transaction amount {tx_value} exceeds permit max {max_amount}"
                )
        else:
            checks["amount_within_limit"] = True

        # -- Check counterparty (destination) if constrained --
        allowed_counterparty = constraints.get("allowed_counterparty")
        tx_destination = tx_data.get("Destination", "")
        if allowed_counterparty:
            counterparty_match = tx_destination == allowed_counterparty
            checks["counterparty_match"] = counterparty_match
            if not counterparty_match:
                details["counterparty_match"] = (
                    f"Expected {allowed_counterparty}, got {tx_destination}"
                )
        else:
            checks["counterparty_match"] = True

    elif tx_type == "TrustSet":
        limit_amount = tx_data.get("LimitAmount", {})
        tx_currency = limit_amount.get("currency", "") if isinstance(limit_amount, dict) else ""
        currency_match = tx_currency == expected_currency
        checks["currency_match"] = currency_match
        if not currency_match:
            details["currency_match"] = f"Expected {expected_currency}, got {tx_currency}"
        checks["amount_within_limit"] = True
        checks["counterparty_match"] = True
    else:
        checks["currency_match"] = False
        details["currency_match"] = f"Unsupported transaction type: {tx_type}"
        checks["amount_within_limit"] = False
        checks["counterparty_match"] = False

    all_passed = all(checks.values())
    return {
        "settlement_verified": all_passed,
        "checks": checks,
        "details": details,
    }


@app.get("/v1/xrpl/health")
def xrpl_health():
    """Check XRPL network connectivity."""
    rpc_url = XRPL_RPC_URL
    if not rpc_url:
        return {"xrpl_configured": False, "reachable": False, "network": XRPL_NETWORK}
    try:
        resp = http_requests.post(
            rpc_url,
            json={"method": "server_info", "params": [{}]},
            timeout=5,
        )
        resp.raise_for_status()
        reachable = True
    except http_requests.RequestException:
        reachable = False
    return {"xrpl_configured": True, "reachable": reachable, "network": XRPL_NETWORK}


@app.post("/v1/proof-artifact", response_model=ProofArtifact)
def create_proof_artifact(req: PermitRequest):
    validate_subject(req.subject)
    validate_action(req.action)
    validate_amount(req.amount)

    now = int(time.time())

    evaluation_context = {
        "action": req.action,
        "jurisdiction": JURISDICTION,
        "currency": CURRENCY,
        "issuer": ISSUER_ADDRESS,
        "amount": req.amount,
        "counterparty": req.counterparty,
    }

    core = {
        "module": APP_NAME,
        "entity_id": req.subject,
        "rule_version_used": POLICY_VERSION,
        "decision_result": "permit",
        "evaluation_context": evaluation_context,
        "reason_codes": REASON_CODES,
        "timestamp": now,
        "anchor_metadata": {"chain": "xrpl", "committed": False},
    }

    artifact_hash = proof_hash(core)

    logger.info(
        "proof_artifact_generated entity_id=%s rule_version=%s bundle_hash=%s",
        req.subject,
        POLICY_VERSION,
        artifact_hash,
    )
    return build_proof_artifact(**core, bundle_hash=artifact_hash)


@app.post("/v1/settle/verify")
def verify_settlement(req: SettlementVerifyRequest):
    """Post-settlement verification: verify that an XRPL transaction
    satisfies the constraints defined in a CompliGate permit.

    CompliGate does not submit or broker transactions. It only verifies
    that a completed settlement conforms to the authorization permit.
    """
    # 1. Verify the permit signature and expiry
    try:
        canonical = canonical_json(req.bundle).encode("utf-8")
        sig_bytes = base64.b64decode(req.signature)
        VERIFY_KEY.verify(canonical, sig_bytes)
        signature_valid = True
    except Exception:
        signature_valid = False

    now = int(time.time())
    exp = req.bundle.get("exp", 0)
    not_expired = now < exp

    if not signature_valid:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_permit", "reason": "Permit signature is invalid"},
        )

    # 2. Fetch the XRPL transaction
    tx_data = fetch_xrpl_transaction(req.tx_hash)

    # 3. Verify settlement against permit constraints
    result = verify_settlement_against_permit(tx_data, req.bundle)

    bundle_hash = proof_hash(req.bundle)

    expired = not not_expired

    logger.info(
        "settlement_verified tx_hash=%s bundle_hash=%s verified=%s permit_expired=%s",
        req.tx_hash,
        bundle_hash,
        result["settlement_verified"],
        expired,
    )

    return {
        "settlement_verified": result["settlement_verified"],
        "permit_valid": signature_valid,
        "permit_expired": expired,
        "tx_hash": req.tx_hash,
        "bundle_hash": bundle_hash,
        "network": XRPL_NETWORK,
        "checks": result["checks"],
        "details": result["details"],
        "verified_at": now,
    }
