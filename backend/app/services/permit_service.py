from __future__ import annotations

import base64
import time
from collections import OrderedDict
from uuid import uuid4

from sqlalchemy.orm import Session

from app.core import config
from app.core.logging import get_logger
from app.core.security import SIGNING_KEY, VERIFY_KEY
from app.models.permit import PermitRequest, PermitResponse, VerifyRequest
from app.models.proof import ProofArtifact
from app.services.compliance import ProviderStatus
from app.services.policy_service import MAX_AMOUNT, evaluate_permit_policy, validate_subject
from app.services.proof_service import create_permit_proof_artifact
from app.services.storage_service import save_permit, save_proof_artifact
from app.utils.canonical_json import canonical_json
from app.utils.hashing import proof_hash

logger = get_logger("main")

RECENT_PERMITS_BY_BUNDLE_HASH: "OrderedDict[str, dict]" = OrderedDict()


def store_recent_permit_context(
    *,
    bundle_hash: str,
    bundle: dict,
    proof_artifact: ProofArtifact,
    issued_at: int,
) -> None:
    RECENT_PERMITS_BY_BUNDLE_HASH[bundle_hash] = {
        "bundle_hash": bundle_hash,
        "bundle": bundle,
        "proof_artifact": proof_artifact.model_dump(),
        "issued_at": issued_at,
    }
    RECENT_PERMITS_BY_BUNDLE_HASH.move_to_end(bundle_hash)
    while len(RECENT_PERMITS_BY_BUNDLE_HASH) > config.PERMIT_CONTEXT_CACHE_MAX_ITEMS:
        RECENT_PERMITS_BY_BUNDLE_HASH.popitem(last=False)


def get_recent_permit_context(bundle_hash: str) -> dict | None:
    return RECENT_PERMITS_BY_BUNDLE_HASH.get(bundle_hash)


def _constraint_value_for(check_status: ProviderStatus | None) -> bool | str:
    """Render a provider status as a bundle-friendly constraint value.

    Approved checks are recorded as ``True`` (or the literal ``"passed"``
    for sanctions, to preserve the existing API shape). Anything else
    (denied / unavailable / missing) is recorded as ``False`` /
    ``"unavailable"`` so the bundle never claims a check succeeded when
    it did not.
    """
    if check_status is ProviderStatus.APPROVED:
        return True
    return False


def _sanctions_constraint_value(check_status: ProviderStatus | None) -> str:
    if check_status is ProviderStatus.APPROVED:
        return "passed"
    if check_status is ProviderStatus.DENIED:
        return "denied"
    return "unavailable"


def create_permit(req: PermitRequest, db: Session | None = None) -> PermitResponse:
    validate_subject(req.subject)

    asset = {
        "issuer": config.ISSUER_ADDRESS,
        "currency": config.CURRENCY,
        "classification": "regulated_stablecoin",
        "regulatory_treatment": "non_security",
        "policy_id": config.POLICY_VERSION,
    }

    policy_result = evaluate_permit_policy(
        subject=req.subject,
        action=req.action,
        amount=req.amount,
        counterparty=req.counterparty,
        asset=asset,
    )
    reason_codes = policy_result["reason_codes"]
    decision_result = policy_result["decision_result"]
    compliance = policy_result["compliance"]

    now = int(time.time())
    exp = now + config.PERMIT_TTL_SECONDS

    within_limit = req.amount <= MAX_AMOUNT if req.amount is not None else True

    kyc_status = compliance.status_for("kyc")
    sanctions_status = compliance.status_for("sanctions")
    reserve_status = compliance.status_for("reserve")

    # Build attestation references from real provider evidence rather
    # than synthetic random hashes. When a provider did not return a
    # reference (e.g. unavailable), the attestation is recorded as None
    # so the proof artifact never claims an attestation that doesn't
    # exist.
    reserve_reference = compliance.reference_for("reserve")
    kyc_reference = compliance.reference_for("kyc")

    bundle = {
        "bundle_id": str(uuid4()),
        "subject": req.subject,
        "action": req.action,
        "asset": asset,
        "constraints": {
            "max_amount": MAX_AMOUNT,
            "amount": req.amount,
            "within_limit": within_limit,
            "allowed_counterparty": req.counterparty,
            "reserve_backed": _constraint_value_for(reserve_status),
            "liquidity_verified": _constraint_value_for(reserve_status),
            "kyc_verified": _constraint_value_for(kyc_status),
            "sanctions_check": _sanctions_constraint_value(sanctions_status),
            "jurisdiction": config.JURISDICTION,
            "freeze_possible": True,
            "clawback_possible": True,
            "trustline_required": True,
        },
        "policy": {
            "version": config.POLICY_VERSION,
            "jurisdiction": config.JURISDICTION,
        },
        "attestations": {
            "kyc_reference": kyc_reference,
            "reserve_reference": reserve_reference,
        },
        "compliance_evidence": compliance.evidence,
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
        "kyc_status": kyc_status.value if kyc_status else "missing",
        "sanctions_status": sanctions_status.value if sanctions_status else "missing",
        "reserve_status": reserve_status.value if reserve_status else "missing",
        "policy_version": config.POLICY_VERSION,
        "expires_in_seconds": config.PERMIT_TTL_SECONDS,
    }

    proof_artifact = create_permit_proof_artifact(
        bundle=bundle,
        reason_codes=reason_codes,
        timestamp=now,
        bundle_hash=bundle_hash,
        decision_result=decision_result,
        compliance_evidence=compliance.evidence,
    )
    save_proof_artifact(bundle_hash=bundle_hash, artifact=proof_artifact, artifact_type="permit_generation")

    store_recent_permit_context(
        bundle_hash=bundle_hash,
        bundle=bundle,
        proof_artifact=proof_artifact,
        issued_at=now,
    )
    logger.info(
        "permit_decision subject=%s action=%s decision=%s exp=%d",
        req.subject,
        req.action,
        decision_result,
        exp,
    )
    permit_response = PermitResponse(
        summary=summary,
        bundle=bundle,
        signature=sig_b64,
        signed_at=now,
        expires_at=exp,
        expires_in_seconds=config.PERMIT_TTL_SECONDS,
        bundle_hash=bundle_hash,
        validity={"single_use": False},
        decision_result=decision_result,
        reason_codes=reason_codes,
        proof_artifact=proof_artifact,
    )
    save_permit(permit_response, db=db)
    return permit_response


def verify_permit_logic(req: VerifyRequest) -> dict:
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
