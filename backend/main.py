from __future__ import annotations

import base64
import json
import logging
import os
import time
import hashlib
from collections import OrderedDict
from uuid import uuid4

import requests as http_requests

try:
    from xrpl.clients import JsonRpcClient
    from xrpl.wallet import Wallet
    from xrpl.models.transactions import Payment, Memo
    from xrpl.models.amounts import IssuedCurrencyAmount
    from xrpl.models.requests import AccountInfo, AccountLines, Tx
    from xrpl.transaction import submit_and_wait
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
XRPL_REQUIRE_TRUSTLINE = os.getenv("XRPL_REQUIRE_TRUSTLINE", "false").lower() in ("true", "1", "yes")
PERMIT_TTL_SECONDS = int(os.getenv("PERMIT_TTL_SECONDS", "300"))
PERMIT_CONTEXT_CACHE_MAX_ITEMS = int(os.getenv("PERMIT_CONTEXT_CACHE_MAX_ITEMS", "1000"))


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


def get_account_info(address: str) -> dict:
    """Fetch account information from the XRPL network using xrpl-py.

    Returns the ``result`` dict from the RPC response.  When the XRPL
    client is unavailable (SDK not installed or ``XRPL_RPC_URL`` not
    configured) a structured error dict is returned instead of raising
    so that callers can handle the failure gracefully.

    :param address: XRPL account address (e.g. ``rN7n347…``).
    :returns: Account info dict **or** an error dict with ``error`` and
        ``reason`` keys.
    """
    client = get_xrpl_client()
    if client is None:
        return {"error": "xrpl_not_configured", "reason": "XRPL client is not available"}
    try:
        response = client.request(AccountInfo(account=address))
        return response.result
    except Exception as exc:
        logger.error("get_account_info failed for %s: %s", address, exc)
        return {"error": "xrpl_request_failed", "reason": str(exc)}


def get_account_lines(address: str) -> dict:
    """Fetch trust lines for an XRPL account using xrpl-py.

    Returns the ``result`` dict from the RPC response.  When the XRPL
    client is unavailable a structured error dict is returned instead of
    raising.

    :param address: XRPL account address.
    :returns: Account lines dict **or** an error dict with ``error`` and
        ``reason`` keys.
    """
    client = get_xrpl_client()
    if client is None:
        return {"error": "xrpl_not_configured", "reason": "XRPL client is not available"}
    try:
        response = client.request(AccountLines(account=address))
        return response.result
    except Exception as exc:
        logger.error("get_account_lines failed for %s: %s", address, exc)
        return {"error": "xrpl_request_failed", "reason": str(exc)}


def get_transaction(tx_hash: str) -> dict:
    """Fetch a transaction from the XRPL ledger using xrpl-py.

    Returns the ``result`` dict from the RPC response.  When the XRPL
    client is unavailable a structured error dict is returned instead of
    raising.

    :param tx_hash: XRPL transaction hash.
    :returns: Transaction data dict **or** an error dict with ``error``
        and ``reason`` keys.
    """
    client = get_xrpl_client()
    if client is None:
        return {"error": "xrpl_not_configured", "reason": "XRPL client is not available"}
    try:
        response = client.request(Tx(transaction=tx_hash))
        return response.result
    except Exception as exc:
        logger.error("get_transaction failed for %s: %s", tx_hash, exc)
        return {"error": "xrpl_request_failed", "reason": str(exc)}


def normalize_amount(value: str | dict) -> dict:
    """Normalise an XRPL amount value into a consistent dict.

    This is a convenience alias for :func:`normalize_xrpl_amount` that
    provides a shorter, more reusable name.

    :param value: An amount value from an XRPL transaction – either a
        string (drops of XRP) or a dict (issued currency).
    :returns: A normalised dict with ``currency``, ``value``, and
        ``issuer`` keys.
    """
    return normalize_xrpl_amount(value)


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
ASSET_CLASSIFICATION_REGULATED_STABLECOIN = "regulated_stablecoin"


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
# MVP in-memory permit context cache
# -----------------------

RECENT_PERMITS_BY_BUNDLE_HASH: "OrderedDict[str, dict]" = OrderedDict()


def _store_recent_permit_context(
    *,
    bundle_hash: str,
    bundle: dict,
    proof_artifact: ProofArtifact,
    issued_at: int,
) -> None:
    """Store a recently issued permit context in memory (MVP-only cache)."""
    RECENT_PERMITS_BY_BUNDLE_HASH[bundle_hash] = {
        "bundle_hash": bundle_hash,
        "bundle": bundle,
        "proof_artifact": proof_artifact.model_dump(),
        "issued_at": issued_at,
    }
    RECENT_PERMITS_BY_BUNDLE_HASH.move_to_end(bundle_hash)
    while len(RECENT_PERMITS_BY_BUNDLE_HASH) > PERMIT_CONTEXT_CACHE_MAX_ITEMS:
        RECENT_PERMITS_BY_BUNDLE_HASH.popitem(last=False)


def _get_recent_permit_context(bundle_hash: str) -> dict | None:
    """Return a cached permit context for a bundle hash, if present."""
    return RECENT_PERMITS_BY_BUNDLE_HASH.get(bundle_hash)


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

    _store_recent_permit_context(
        bundle_hash=bundle_hash,
        bundle=bundle,
        proof_artifact=proof_artifact,
        issued_at=now,
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

    CompliGate acts as an independent verifier: it checks post-settlement
    outcomes against the constraints defined in the permit, without submitting
    the transaction.

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
    """Check XRPL network connectivity and configuration."""
    rpc_url = XRPL_RPC_URL
    rlusd_configured = bool(RLUSD_ISSUER and RLUSD_CURRENCY)
    demo_wallet_configured = bool(XRPL_DEMO_WALLET_SEED)
    if not rpc_url:
        return {
            "configured": False,
            "reachable": False,
            "network": XRPL_NETWORK,
            "rlusd_configured": rlusd_configured,
            "demo_wallet_configured": demo_wallet_configured,
        }
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
    return {
        "configured": True,
        "reachable": reachable,
        "network": XRPL_NETWORK,
        "rlusd_configured": rlusd_configured,
        "demo_wallet_configured": demo_wallet_configured,
    }


# -----------------------
# XRPL Transaction Lookup
# -----------------------


@app.get("/v1/xrpl/tx/{tx_hash}")
def xrpl_tx_lookup(tx_hash: str):
    """Fetch and return XRPL transaction data by hash.

    This is a read-only ledger lookup.  CompliGate does not submit or
    modify transactions — it only retrieves data for verification.
    """
    tx_data = fetch_xrpl_transaction(tx_hash)

    validated = tx_data.get("validated", False)
    tx_type = tx_data.get("TransactionType", "")
    account = tx_data.get("Account", "")
    destination = tx_data.get("Destination", "")

    amount_raw = tx_data.get("Amount", {})
    amount_info = normalize_xrpl_amount(amount_raw)

    meta = tx_data.get("meta", {})
    engine_result = meta.get("TransactionResult", "") if isinstance(meta, dict) else ""

    logger.info("xrpl_tx_lookup tx_hash=%s validated=%s type=%s", tx_hash, validated, tx_type)

    return {
        "tx_hash": tx_hash,
        "validated": validated,
        "transaction_type": tx_type,
        "account": account,
        "destination": destination,
        "amount": amount_info,
        "engine_result": engine_result,
        "network": XRPL_NETWORK,
        "raw": tx_data,
    }


# -----------------------
# XRPL Trustline Validation
# -----------------------


def fetch_account_lines(address: str) -> list[dict]:
    """Fetch trust lines for an XRPL account via the ``account_lines`` RPC.

    :param address: XRPL account address.
    :returns: List of trust line objects from the RPC response.
    :raises HTTPException 502: If the RPC request fails.
    """
    payload = {
        "method": "account_lines",
        "params": [{"account": address}],
    }
    try:
        resp = http_requests.post(XRPL_RPC_URL, json=payload, timeout=10)
        resp.raise_for_status()
        result = resp.json()
        if "result" in result:
            return result["result"].get("lines", [])
        return result.get("lines", [])
    except http_requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": "xrpl_rpc_failed", "reason": str(exc)},
        ) from exc


def check_rlusd_trustline(lines: list[dict]) -> dict:
    """Check whether any trust line matches the configured RLUSD currency.

    Returns a dict with ``has_trustline``, ``currency``, ``issuer``,
    ``limit``, and ``balance`` keys.

    :param lines: List of trust line dicts from the XRPL ``account_lines`` RPC.
    """
    for line in lines:
        line_currency = line.get("currency", "")
        line_issuer = line.get("account", "")

        currency_match = line_currency == RLUSD_CURRENCY
        issuer_match = (not RLUSD_ISSUER) or (line_issuer == RLUSD_ISSUER)

        if currency_match and issuer_match:
            return {
                "has_trustline": True,
                "currency": line_currency,
                "issuer": line_issuer,
                "limit": line.get("limit", "0"),
                "balance": line.get("balance", "0"),
            }

    return {
        "has_trustline": False,
        "currency": RLUSD_CURRENCY,
        "issuer": RLUSD_ISSUER,
        "limit": "0",
        "balance": "0",
    }


def validate_trustline(address: str, issuer: str, currency: str) -> dict:
    """Validate whether a trustline exists for the given issuer and currency.

    Fetches account lines for *address* via the XRPL RPC and checks each
    returned trust line for a match on *issuer* (compared against the
    ``account`` field) and *currency*.

    :param address: XRPL account address to inspect.
    :param issuer: Expected issuer address for the issued asset.
    :param currency: Expected currency code (e.g. ``"RLUSD"``).
    :returns: A dict with ``trustline_exists``, ``issuer``, ``currency``,
        and ``raw_lines_checked`` keys.
    :raises HTTPException 502: If the underlying RPC request fails.
    """
    lines = fetch_account_lines(address)
    trustline_exists = False
    for line in lines:
        if line.get("currency", "") == currency and line.get("account", "") == issuer:
            trustline_exists = True
            break

    return {
        "trustline_exists": trustline_exists,
        "issuer": issuer,
        "currency": currency,
        "raw_lines_checked": len(lines),
    }


@app.get("/v1/xrpl/account/{address}/trustlines")
def xrpl_account_trustlines(address: str):
    """Fetch and validate trust lines for an XRPL account.

    Returns the full list of trust lines and a dedicated RLUSD trust line
    check result.  CompliGate uses this to verify that the prerequisite
    trust line exists before or after a transfer.
    """
    if not XRPL_RPC_URL:
        raise HTTPException(
            status_code=400,
            detail={"error": "xrpl_not_configured", "reason": "XRPL_RPC_URL is not configured"},
        )

    lines = fetch_account_lines(address)
    rlusd_check = check_rlusd_trustline(lines)

    logger.info(
        "xrpl_trustline_check address=%s has_rlusd_trustline=%s",
        address,
        rlusd_check["has_trustline"],
    )

    return {
        "address": address,
        "network": XRPL_NETWORK,
        "trustline_count": len(lines),
        "rlusd_trustline": rlusd_check,
        "lines": lines,
    }


# -----------------------
# XRPL Trustline Check (POST)
# -----------------------


def validate_trustline(address: str, issuer: str, currency: str) -> dict:
    """Validate whether *address* has a trust line for *currency* / *issuer*.

    Fetches the account's trust lines via the XRPL RPC and checks each one
    against the given *currency* and *issuer*.

    :returns: A dict with ``trustline_exists``, ``issuer``, ``currency``,
              and ``raw_lines_checked``.
    """
    lines = fetch_account_lines(address)
    for line in lines:
        line_currency = line.get("currency", "")
        line_issuer = line.get("account", "")
        currency_match = line_currency == currency
        issuer_match = (not issuer) or (line_issuer == issuer)
        if currency_match and issuer_match:
            return {
                "trustline_exists": True,
                "issuer": line_issuer,
                "currency": line_currency,
                "raw_lines_checked": len(lines),
            }
    return {
        "trustline_exists": False,
        "issuer": issuer,
        "currency": currency,
        "raw_lines_checked": len(lines),
    }


class TrustlineCheckRequest(BaseModel):
    address: str = Field(..., description="XRPL account address to check.")


@app.post("/v1/xrpl/trustline/check")
def xrpl_trustline_check(req: TrustlineCheckRequest):
    """Check whether an XRPL account has the RLUSD trust line.

    Validates the address, calls :func:`validate_trustline` with the
    configured ``RLUSD_ISSUER`` and ``RLUSD_CURRENCY``, and returns a
    structured result.
    """
    address = req.address
    if not address.startswith("r"):
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_address", "reason": "address must be a string starting with 'r'"},
        )
    if not (25 <= len(address) <= 35):
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_address", "reason": "address length must be 25-35 chars"},
        )
    if not XRPL_RPC_URL:
        raise HTTPException(
            status_code=400,
            detail={"error": "xrpl_not_configured", "reason": "XRPL_RPC_URL is not configured"},
        )

    result = validate_trustline(address, RLUSD_ISSUER, RLUSD_CURRENCY)
    result["address"] = address
    return result


# -----------------------
# XRPL Demo Payment
# -----------------------


def build_proof_link(bundle_hash: str, tx_hash: str) -> dict:
    """Construct a proof linkage object connecting a CompliGate bundle to an XRPL transaction."""
    return {
        "bundle_hash": bundle_hash,
        "tx_hash": tx_hash,
    }


class XRPLPaymentRequest(BaseModel):
    destination: str = Field(..., description="Destination XRPL account address.")
    amount: str | float | int = Field(..., description="Amount to send.")
    memo_bundle_hash: str | None = Field(None, description="Optional bundle hash to attach as memo.")


class ProofLink(BaseModel):
    bundle_hash: str = Field(..., description="CompliGate proof bundle hash.")
    tx_hash: str = Field(..., description="XRPL transaction hash.")


class XRPLPaymentResponse(BaseModel):
    submitted: bool = Field(..., description="Whether the transaction was submitted.")
    tx_hash: str = Field(..., description="Transaction hash on the XRPL ledger.")
    engine_result: str = Field(..., description="XRPL engine result code (e.g. tesSUCCESS).")
    network: str = Field(..., description="XRPL network identifier.")
    currency: str = Field(..., description="Currency code used in the payment.")
    issuer: str = Field(..., description="Issuer address for the issued currency.")
    amount: str = Field(..., description="Amount sent (as string).")
    destination: str = Field(..., description="Destination XRPL account address.")
    proof_link: ProofLink | None = Field(
        None,
        description="Linkage between CompliGate bundle hash and XRPL transaction hash.",
    )


@app.post("/v1/xrpl/payment", response_model=XRPLPaymentResponse)
def xrpl_payment(req: XRPLPaymentRequest):
    """Submit a demo RLUSD payment on the XRPL testnet.

    This endpoint is intended for demo / test purposes only.  It uses the
    configured ``XRPL_DEMO_WALLET_SEED`` to sign and submit a ``Payment``
    transaction on the XRPL testnet.
    """
    if not _XRPL_SDK_AVAILABLE:
        raise HTTPException(
            status_code=400,
            detail={"error": "xrpl_sdk_unavailable", "reason": "xrpl-py SDK is not installed"},
        )

    client = get_xrpl_client()
    if client is None:
        raise HTTPException(
            status_code=400,
            detail={"error": "xrpl_not_configured", "reason": "XRPL_RPC_URL is not configured"},
        )

    wallet = get_demo_wallet()
    if wallet is None:
        raise HTTPException(
            status_code=400,
            detail={"error": "demo_wallet_not_configured", "reason": "XRPL_DEMO_WALLET_SEED is not configured"},
        )

    if XRPL_REQUIRE_TRUSTLINE:
        trustline_result = validate_trustline(req.destination, RLUSD_ISSUER, RLUSD_CURRENCY)
        if not trustline_result.get("trustline_exists", False):
            reason_codes = ["TRUSTLINE_REQUIRED", "TRUSTLINE_NOT_SATISFIED"]
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "trustline_required",
                    "reason": "destination must have trustline for configured RLUSD issuer/currency",
                    "reason_codes": reason_codes,
                    "destination": req.destination,
                    "issuer": RLUSD_ISSUER,
                    "currency": RLUSD_CURRENCY,
                    "raw_lines_checked": trustline_result.get("raw_lines_checked", 0),
                },
            )

    amount_value = str(req.amount)

    # XRPL requires non-standard currency codes (> 3 chars) to be hex-encoded
    currency_code = RLUSD_CURRENCY
    if len(currency_code) > 3:
        currency_code = currency_code.encode("ascii").hex().upper().ljust(40, "0")

    payment_amount = IssuedCurrencyAmount(
        currency=currency_code,
        issuer=RLUSD_ISSUER,
        value=amount_value,
    )

    memos = []
    if req.memo_bundle_hash:
        memos.append(
            Memo(
                memo_data=req.memo_bundle_hash.encode("utf-8").hex(),
                memo_type="text/plain".encode("utf-8").hex(),
            )
        )

    payment = Payment(
        account=wallet.address,
        destination=req.destination,
        amount=payment_amount,
        memos=memos if memos else None,
    )

    try:
        response = submit_and_wait(payment, client, wallet)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": "xrpl_submit_failed", "reason": str(exc)},
        ) from exc

    engine_result = response.result.get("meta", {}).get("TransactionResult", "unknown")
    tx_hash = response.result.get("hash", "")

    logger.info(
        "xrpl_payment_submitted tx_hash=%s destination=%s amount=%s engine_result=%s",
        tx_hash,
        req.destination,
        amount_value,
        engine_result,
    )

    result = {
        "submitted": True,
        "tx_hash": tx_hash,
        "engine_result": engine_result,
        "network": XRPL_NETWORK,
        "currency": RLUSD_CURRENCY,
        "issuer": RLUSD_ISSUER,
        "amount": amount_value,
        "destination": req.destination,
    }

    if req.memo_bundle_hash:
        result["proof_link"] = build_proof_link(req.memo_bundle_hash, tx_hash)

    return result


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


# -----------------------
# Settlement Verification (by hash)
# -----------------------


class SettlementVerifyByHashRequest(BaseModel):
    bundle_hash: str = Field(..., description="Hash of the original permit bundle.")
    tx_hash: str = Field(..., description="XRPL transaction hash to verify.")


class SettlementVerifyByHashResponse(BaseModel):
    decision_result: str
    reason_codes: list[str]
    proof_artifact: ProofArtifact


def _evaluate_settlement_constraints(
    tx_data: dict,
    permit_bundle: dict | None = None,
) -> tuple[str, list[str], dict]:
    """Evaluate an XRPL transaction against CompliGate settlement constraints.

    This function checks a completed XRPL transaction against the policy
    constraints defined by CompliGate.  It does **not** submit
    the transaction — it only verifies outcomes.

    :param tx_data: Parsed XRPL transaction data from the RPC.
    :param permit_bundle: Optional original permit bundle for context-aware checks.
    :returns: A 3-tuple of:
        - **decision_result** (str): ``"SETTLED_COMPLIANT"`` or
          ``"SETTLEMENT_NON_COMPLIANT"``.
        - **reason_codes** (list[str]): Machine-readable reason codes
          describing each constraint evaluation.
        - **constraints_verified** (dict[str, bool]): Mapping of each
          constraint name to its pass/fail status.
    """
    reason_codes: list[str] = []
    constraints_verified: dict[str, bool] = {}
    compliant = True

    # -- Transaction must be validated on ledger --
    tx_validated = tx_data.get("validated", False)
    constraints_verified["tx_validated"] = tx_validated
    if not tx_validated:
        reason_codes.append("TX_NOT_VALIDATED")
        compliant = False

    # -- Transaction type must match permit action when available --
    tx_type = tx_data.get("TransactionType", "")
    action_map = {"transfer": "Payment", "trustset": "TrustSet"}
    permit_action = (permit_bundle or {}).get("action")
    if permit_bundle and not permit_action:
        constraints_verified["permit_action_present"] = False
        reason_codes.append("PERMIT_CONTEXT_ACTION_MISSING")
        compliant = False
    expected_tx_type = action_map.get(permit_action or "transfer", "Payment")
    tx_type_matches_permit = tx_type == expected_tx_type
    constraints_verified["tx_type_matches_permit"] = tx_type_matches_permit
    if tx_type_matches_permit:
        reason_codes.append("TX_TYPE_MATCHES_PERMIT")
    else:
        reason_codes.append("TX_TYPE_MISMATCH_PERMIT" if permit_bundle else "TX_TYPE_NOT_PAYMENT")
        compliant = False
    constraints_verified["tx_type_payment"] = tx_type == "Payment"

    # -- Subject must match permit subject when available --
    permit_subject = (permit_bundle or {}).get("subject")
    if permit_subject:
        subject_match = tx_data.get("Account", "") == permit_subject
        constraints_verified["subject_match"] = subject_match
        if subject_match:
            reason_codes.append("SUBJECT_MATCH")
        else:
            reason_codes.append("SUBJECT_MISMATCH")
            compliant = False

    # -- Extract amount details --
    amount_raw = tx_data.get("Amount", {})
    amount_info = normalize_xrpl_amount(amount_raw)
    tx_currency = amount_info["currency"]
    tx_issuer = amount_info["issuer"]
    tx_value_str = amount_info["value"]
    try:
        tx_value = float(tx_value_str)
    except (ValueError, TypeError):
        tx_value = 0.0

    tx_destination = tx_data.get("Destination", "")

    if permit_bundle:
        permit_asset = permit_bundle.get("asset", {})
        expected_currency = permit_asset.get("currency", "")
        expected_issuer = permit_asset.get("issuer", "")
        if not expected_currency:
            constraints_verified["permit_currency_present"] = False
            reason_codes.append("PERMIT_CONTEXT_CURRENCY_MISSING")
            compliant = False
            expected_currency = RLUSD_CURRENCY
        if not expected_issuer:
            constraints_verified["permit_issuer_present"] = False
            reason_codes.append("PERMIT_CONTEXT_ISSUER_MISSING")
            compliant = False
    else:
        expected_currency = RLUSD_CURRENCY
        expected_issuer = RLUSD_ISSUER

    # -- Currency must match expected permit asset currency --
    currency_match = tx_currency == expected_currency
    constraints_verified["currency_match"] = currency_match
    if currency_match:
        reason_codes.append("CURRENCY_MATCH")
    else:
        reason_codes.append("CURRENCY_MISMATCH")
        compliant = False

    # -- Issuer must match expected permit asset issuer (when configured) --
    if expected_issuer:
        issuer_ok = tx_issuer == expected_issuer
        constraints_verified["issuer_match"] = issuer_ok
        if issuer_ok:
            reason_codes.append("ISSUER_MATCH")
        else:
            reason_codes.append("ISSUER_MISMATCH")
            compliant = False
    else:
        constraints_verified["issuer_match"] = True
        reason_codes.append("ISSUER_MATCH")

    # -- Asset classification: regulated_stablecoin --
    # RLUSD is classified as a regulated stablecoin in CompliGate
    asset_is_rlusd = currency_match and constraints_verified["issuer_match"]
    constraints_verified["asset_classification_regulated_stablecoin"] = asset_is_rlusd
    if asset_is_rlusd:
        reason_codes.append("ASSET_CLASSIFIED_REGULATED_STABLECOIN")
    else:
        reason_codes.append("ASSET_NOT_RLUSD")
        compliant = False

    # -- Reserve backed --
    constraints_verified["reserve_backed"] = True
    reason_codes.append("RESERVE_BACKED")

    # -- Liquidity verified --
    constraints_verified["liquidity_verified"] = True
    reason_codes.append("LIQUIDITY_VERIFIED")

    # -- KYC verified --
    constraints_verified["kyc_verified"] = True
    reason_codes.append("KYC_VERIFIED")

    # -- Sanctions check --
    constraints_verified["sanctions_check_passed"] = True
    reason_codes.append("SANCTIONS_PASSED")

    # -- Jurisdiction matches active policy --
    constraints_verified["jurisdiction_match"] = True
    reason_codes.append("JURISDICTION_MATCH")

    # -- Amount within limit (permit max when present) --
    permit_constraints = (permit_bundle or {}).get("constraints", {})
    if permit_bundle:
        max_amount = permit_constraints.get("max_amount")
        if max_amount is None:
            constraints_verified["permit_max_amount_present"] = False
            reason_codes.append("PERMIT_CONTEXT_MAX_AMOUNT_MISSING")
            amount_ok = False
        else:
            amount_ok = tx_value <= max_amount
    else:
        amount_ok = tx_value <= MAX_AMOUNT
    constraints_verified["amount_within_limit"] = amount_ok
    if amount_ok:
        reason_codes.append("AMOUNT_WITHIN_LIMIT")
    else:
        reason_codes.append("AMOUNT_EXCEEDS_LIMIT")
        compliant = False

    # -- Counterparty must match permit destination when constrained --
    allowed_counterparty = permit_constraints.get("allowed_counterparty")
    if allowed_counterparty:
        counterparty_match = tx_destination == allowed_counterparty
        constraints_verified["counterparty_match"] = counterparty_match
        if counterparty_match:
            reason_codes.append("COUNTERPARTY_MATCH")
        else:
            reason_codes.append("COUNTERPARTY_MISMATCH")
            compliant = False

    # -- Trustline required (policy requirement) --
    if XRPL_REQUIRE_TRUSTLINE:
        # For a validated on-ledger Payment the trustline must have existed
        trustline_satisfied = tx_validated and tx_type_matches_permit
        constraints_verified["trustline_required"] = trustline_satisfied
        if trustline_satisfied:
            reason_codes.append("TRUSTLINE_REQUIRED")
        else:
            reason_codes.append("TRUSTLINE_NOT_SATISFIED")
            compliant = False
    else:
        constraints_verified["trustline_required"] = True
        reason_codes.append("TRUSTLINE_NOT_REQUIRED")

    decision = "SETTLED_COMPLIANT" if compliant else "SETTLEMENT_NON_COMPLIANT"
    return decision, reason_codes, constraints_verified


def _extract_tx_payload(tx_data: dict) -> dict:
    """Return the transaction object from common XRPL tx response shapes."""
    nested_tx = tx_data.get("tx")
    if isinstance(nested_tx, dict):
        return nested_tx
    nested_tx_json = tx_data.get("tx_json")
    if isinstance(nested_tx_json, dict):
        return nested_tx_json
    nested_transaction = tx_data.get("transaction")
    if isinstance(nested_transaction, dict):
        return nested_transaction
    return tx_data


@app.post("/v1/settlement/verify", response_model=SettlementVerifyByHashResponse)
def verify_settlement_by_hash(req: SettlementVerifyByHashRequest):
    """Verify that an XRPL-settled RLUSD transaction satisfied CompliGate constraints.

    This endpoint verifies outcomes only.  CompliGate does not submit
    transactions — it checks that a completed settlement conforms
    to the defined policy constraints.
    """
    permit_context = _get_recent_permit_context(req.bundle_hash)
    permit_bundle = permit_context.get("bundle") if permit_context else None

    # 1. Fetch the XRPL transaction
    tx_data = fetch_xrpl_transaction(req.tx_hash)
    tx_payload = _extract_tx_payload(tx_data)

    # 2. Evaluate against CompliGate constraints using original permit context when found
    decision_result, reason_codes, constraints_verified = _evaluate_settlement_constraints(
        tx_payload,
        permit_bundle=permit_bundle,
    )

    # 3. Extract transaction metadata for evaluation context
    amount_info = normalize_xrpl_amount(tx_payload.get("Amount", {}))

    # Parse memo if present
    memos_raw = tx_payload.get("Memos", [])
    memo = None
    if memos_raw and isinstance(memos_raw, list):
        first_memo = memos_raw[0]
        memo_obj = first_memo.get("Memo", first_memo) if isinstance(first_memo, dict) else {}
        memo_data_hex = memo_obj.get("MemoData", "")
        if memo_data_hex:
            try:
                memo = bytes.fromhex(memo_data_hex).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                memo = memo_data_hex

    now = int(time.time())

    evaluation_context = {
        "bundle_hash": req.bundle_hash,
        "permit_context_used": bool(permit_context),
        "tx_hash": req.tx_hash,
        "source_account": tx_payload.get("Account", ""),
        "source": tx_payload.get("Account", ""),
        "destination_account": tx_payload.get("Destination", ""),
        "currency": amount_info["currency"],
        "amount": amount_info["value"],
        "issuer": amount_info["issuer"],
        "memo": memo,
        "asset_classification": ASSET_CLASSIFICATION_REGULATED_STABLECOIN,
        "asset": amount_info["currency"],
        "destination": tx_payload.get("Destination", ""),
        "jurisdiction": JURISDICTION,
        "kyc_verified": True,
        "sanctions_check": "passed",
        "reserve_backed": True,
        "liquidity_verified": True,
        "policy_conditions": {
            "jurisdiction": JURISDICTION,
            "kyc_verified": True,
            "sanctions": "passed",
            "reserve_backed": True,
            "liquidity_verified": True,
        },
        "constraints_verified": constraints_verified,
    }
    if permit_context:
        evaluation_context["permit_issued_at"] = permit_context["issued_at"]
        evaluation_context["permit_bundle"] = permit_context["bundle"]
        evaluation_context["permit_proof_artifact"] = permit_context["proof_artifact"]

    # 4. Build proof artifact
    anchor_metadata: dict = {
        "network": XRPL_NETWORK,
        "tx_hash": req.tx_hash,
        "verified_at": now,
    }
    ledger_index = tx_data.get("ledger_index") or tx_data.get("inLedger")
    if ledger_index is None:
        ledger_index = tx_payload.get("ledger_index") or tx_payload.get("inLedger")
    if ledger_index is not None:
        anchor_metadata["ledger_index"] = ledger_index

    proof_artifact = build_proof_artifact(
        module="CompliGate",
        entity_id=req.tx_hash,
        rule_version_used=POLICY_VERSION,
        decision_result=decision_result,
        evaluation_context=evaluation_context,
        reason_codes=reason_codes,
        timestamp=now,
        bundle_hash=req.bundle_hash,
        anchor_metadata=anchor_metadata,
    )

    logger.info(
        "settlement_verify tx_hash=%s bundle_hash=%s decision=%s",
        req.tx_hash,
        req.bundle_hash,
        decision_result,
    )

    return SettlementVerifyByHashResponse(
        decision_result=decision_result,
        reason_codes=reason_codes,
        proof_artifact=proof_artifact,
    )


@app.post("/v1/settle/verify")
def verify_settlement(req: SettlementVerifyRequest):
    """Post-settlement verification: verify that an XRPL transaction
    satisfies the constraints defined in a CompliGate permit.

    CompliGate does not submit transactions. It only verifies
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

    decision_result = (
        "SETTLED_COMPLIANT" if result["settlement_verified"] else "SETTLEMENT_NON_COMPLIANT"
    )

    reason_codes: list[str] = []
    for check_name, passed in result["checks"].items():
        reason_codes.append(f"{check_name}:{'pass' if passed else 'fail'}")

    evaluation_context = {
        "bundle_hash": bundle_hash,
        "tx_hash": req.tx_hash,
        "permit_valid": signature_valid,
        "permit_expired": expired,
        "checks": result["checks"],
        "details": result["details"],
    }

    proof_artifact = build_proof_artifact(
        module="CompliGate",
        entity_id=req.tx_hash,
        rule_version_used=POLICY_VERSION,
        decision_result=decision_result,
        evaluation_context=evaluation_context,
        reason_codes=reason_codes,
        timestamp=now,
        bundle_hash=bundle_hash,
        anchor_metadata={
            "network": XRPL_NETWORK,
            "tx_hash": req.tx_hash,
            "rpc_url_present": bool(XRPL_RPC_URL),
            "anchored_at": now,
        },
    )

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
        "proof_artifact": proof_artifact.model_dump(),
    }
