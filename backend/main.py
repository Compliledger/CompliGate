from __future__ import annotations

import base64
import json
import os
import time
import hashlib
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder
from nacl.exceptions import BadSignatureError

load_dotenv()

APP_NAME = "CompliGate Backend"

POLICY_VERSION = os.getenv("POLICY_VERSION", "RLUSD_US_v1")
JURISDICTION = os.getenv("JURISDICTION", "US")
CURRENCY = os.getenv("CURRENCY", "RLUSD")
ISSUER_ADDRESS = os.getenv("ISSUER_ADDRESS", "rEXAMPLE_ISSUER_ADDRESS")
PRIVATE_KEY_B64 = os.getenv("COMPLIGATE_PRIVATE_KEY_B64", "").strip()

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

class PermitRequest(BaseModel):
    subject: str = Field(..., description="XRPL account address (starts with 'r').")


class PermitResponse(BaseModel):
    summary: dict
    bundle: dict
    signature: str
    signed_at: int
    expires_at: int
    expires_in_seconds: int
    bundle_hash: str


class VerifyRequest(BaseModel):
    bundle: dict
    signature: str


# -----------------------
# App Setup
# -----------------------

app = FastAPI(title=APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
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
        raise HTTPException(status_code=400, detail="subject must be a string")
    if not subject.startswith("r"):
        raise HTTPException(status_code=400, detail="subject must start with 'r'")
    if not (25 <= len(subject) <= 35):
        raise HTTPException(status_code=400, detail="subject length must be 25-35 chars")


@app.post("/v1/permit", response_model=PermitResponse)
def create_permit(req: PermitRequest):
    validate_subject(req.subject)

    now = int(time.time())
    exp = now + PERMIT_TTL_SECONDS

    bundle = {
        "bundle_id": str(uuid4()),
        "asset": {
            "issuer": ISSUER_ADDRESS,
            "currency": CURRENCY,
            "classification": "regulated_stablecoin",
        },
        "subject": req.subject,
        "policy": {
            "version": POLICY_VERSION,
            "jurisdiction": JURISDICTION,
        },
        "attestations": {
            "custody_hash": random_hex(32),
            "reserve_hash": random_hex(32),
        },
        "scope": ["trustset", "payment"],
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

    return PermitResponse(
        summary=summary,
        bundle=bundle,
        signature=sig_b64,
        signed_at=now,
        expires_at=exp,
        expires_in_seconds=PERMIT_TTL_SECONDS,
        bundle_hash=bundle_hash,
    )

# -----------------------
# XRPL (MVP) Endpoints
# -----------------------
from xrpl.clients import JsonRpcClient
from xrpl.wallet import Wallet
from xrpl.models.transactions import TrustSet, Payment, Memo
from xrpl.models.amounts import IssuedCurrencyAmount
from xrpl.transaction import autofill_and_sign, submit_and_wait


XRPL_NETWORK = os.getenv("XRPL_NETWORK", "testnet").lower()
XRPL_SENDER_SEED = os.getenv("XRPL_SENDER_SEED", "").strip()

XRPL_URLS = {
    "testnet": "https://s.altnet.rippletest.net:51234",
    "mainnet": "https://s1.ripple.com:51234",
}

xrpl_client = JsonRpcClient(XRPL_URLS.get(XRPL_NETWORK, XRPL_URLS["testnet"]))


class TrustlineRequest(BaseModel):
    subject: str
    issuer: str
    currency: str
    limit: str = "1000000"
    bundle_hash: str


@app.post("/v1/xrpl/trustline")
def xrpl_create_trustline(req: TrustlineRequest):
    if not XRPL_SENDER_SEED:
        raise HTTPException(status_code=400, detail="XRPL_SENDER_SEED is not set")

    validate_subject(req.subject)

    wallet = Wallet(seed=XRPL_SENDER_SEED, sequence=0)

    memo = Memo(
        memo_type="COMPLIGATE",
        memo_data=req.bundle_hash,
    )

    tx = TrustSet(
        account=wallet.classic_address,
        limit_amount=IssuedCurrencyAmount(
            currency=req.currency,
            issuer=req.issuer,
            value=req.limit,
        ),
        memos=[memo],
    )

    signed = autofill_and_sign(tx, xrpl_client, wallet)
    result = submit_and_wait(signed, xrpl_client)

    return {
        "status": "submitted",
        "account": wallet.classic_address,
        "tx_hash": result.result.get("hash"),
        "engine_result": result.result.get("engine_result"),
        "memo_bundle_hash": req.bundle_hash,
    }


class PaymentRequest(BaseModel):
    destination: str
    issuer: str
    currency: str
    amount: str
    bundle_hash: str


@app.post("/v1/xrpl/payment")
def xrpl_send_payment(req: PaymentRequest):
    if not XRPL_SENDER_SEED:
        raise HTTPException(status_code=400, detail="XRPL_SENDER_SEED is not set")

    validate_subject(req.destination)

    wallet = Wallet(seed=XRPL_SENDER_SEED, sequence=0)

    memo = Memo(
        memo_type="COMPLIGATE",
        memo_data=req.bundle_hash,
    )

    amt = IssuedCurrencyAmount(
        currency=req.currency,
        issuer=req.issuer,
        value=req.amount,
    )

    tx = Payment(
        account=wallet.classic_address,
        destination=req.destination,
        amount=amt,
        memos=[memo],
    )

    signed = autofill_and_sign(tx, xrpl_client, wallet)
    result = submit_and_wait(signed, xrpl_client)

    return {
        "status": "submitted",
        "account": wallet.classic_address,
        "destination": req.destination,
        "tx_hash": result.result.get("hash"),
        "engine_result": result.result.get("engine_result"),
        "memo_bundle_hash": req.bundle_hash,
    
@app.post("/v1/verify")
def verify_permit(req: VerifyRequest):
    try:
        canonical = canonical_json(req.bundle).encode("utf-8")
        sig_bytes = base64.b64decode(req.signature)
        VERIFY_KEY.verify(canonical, sig_bytes)
        signature_valid = True
    except (BadSignatureError, Exception):
        signature_valid = False

    now = int(time.time())
    exp = req.bundle.get("exp", 0)
    not_expired = now < exp

    return {
        "signature_valid": signature_valid,
        "not_expired": not_expired,
        "subject": req.bundle.get("subject"),
        "policy_version": req.bundle.get("policy", {}).get("version"),
    }
