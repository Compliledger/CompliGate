from __future__ import annotations

import base64
import json
import logging
import os
import time
import hashlib
from uuid import uuid4

import requests as http_requests

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

ALGORAND_ADAPTER_URL = os.getenv("ALGORAND_ADAPTER_URL", "")
PERMIT_TTL_SECONDS = 300  # 5 minutes


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
# Models
# -----------------------

SUPPORTED_ACTIONS = {"transfer", "trustset"}
MAX_AMOUNT = 1000


class PermitRequest(BaseModel):
    subject: str = Field(..., description="XRPL account address (starts with 'r').")
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


class VerifyRequest(BaseModel):
    bundle: dict
    signature: str


class CommitRequest(BaseModel):
    bundle_hash: str
    subject: str
    policy_id: str
    exp: int
    action: str


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

    bundle = {
        "bundle_id": str(uuid4()),
        "subject": req.subject,
        "action": req.action,
        "asset": {
            "issuer": ISSUER_ADDRESS,
            "currency": CURRENCY,
            "classification": "regulated_stablecoin",
            "policy_id": POLICY_VERSION,
        },
        "constraints": {
            "max_amount": MAX_AMOUNT,
            "allowed_counterparty": req.counterparty,
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
# Algorand Adapter
# -----------------------

def call_algorand_adapter(payload: dict) -> dict:
    """Forward a commit request to the Algorand adapter service.

    :param payload: Dict with keys bundle_hash, subject, policy_id, exp, action.
    :returns: Parsed JSON response from the adapter (expected to contain 'tx_id').
    :raises HTTPException 502: If ALGORAND_ADAPTER_URL is not set or the request fails.
    """
    adapter_url = ALGORAND_ADAPTER_URL
    if not adapter_url:
        raise HTTPException(
            status_code=502,
            detail={"error": "adapter_commit_failed", "reason": "ALGORAND_ADAPTER_URL is not configured"},
        )
    try:
        resp = http_requests.post(f"{adapter_url}/v1/commit", json=payload, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except http_requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": "adapter_commit_failed", "reason": str(exc)},
        ) from exc


@app.get("/v1/adapter-health")
def adapter_health():
    adapter_url = ALGORAND_ADAPTER_URL
    if not adapter_url:
        return {"adapter_configured": False, "reachable": False}
    try:
        resp = http_requests.get(f"{adapter_url}/health", timeout=5)
        resp.raise_for_status()
        reachable = True
    except http_requests.RequestException:
        reachable = False
    return {"adapter_configured": True, "reachable": reachable}


@app.post("/v1/commit")
def commit_bundle(req: CommitRequest):
    validate_subject(req.subject)
    validate_action(req.action)
    if not req.bundle_hash:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_bundle_hash", "reason": "bundle_hash is required"},
        )
    if not req.policy_id:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_policy_id", "reason": "policy_id is required"},
        )
    payload = {
        "bundle_hash": req.bundle_hash,
        "subject": req.subject,
        "policy_id": req.policy_id,
        "exp": req.exp,
        "action": req.action,
    }
    logger.info("commit_requested bundle_hash=%s", req.bundle_hash)
    try:
        result = call_algorand_adapter(payload)
    except HTTPException as exc:
        logger.error("commit_failed reason=%s", exc.detail)
        raise
    logger.info("commit_success tx_id=%s", result.get("tx_id"))
    return {
        "committed": True,
        "algorand_tx_id": result.get("tx_id"),
        "bundle_hash": req.bundle_hash,
        "adapter_response": result,
    }
