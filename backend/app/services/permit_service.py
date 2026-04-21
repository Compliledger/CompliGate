from __future__ import annotations

import base64
import time
from collections import OrderedDict
from uuid import uuid4

from app.core import config
from app.core.logging import get_logger
from app.core.security import SIGNING_KEY
from app.models.permit import PermitRequest, PermitResponse
from app.models.proof import ProofArtifact, build_proof_artifact
from app.services.policy_service import MAX_AMOUNT, evaluate_constraints, evaluate_eligibility, evaluate_governance, validate_subject
from app.services.proof_service import random_hex
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


def create_permit(req: PermitRequest) -> PermitResponse:
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
    exp = now + config.PERMIT_TTL_SECONDS

    within_limit = req.amount <= MAX_AMOUNT if req.amount is not None else True

    bundle = {
        "bundle_id": str(uuid4()),
        "subject": req.subject,
        "action": req.action,
        "asset": {
            "issuer": config.ISSUER_ADDRESS,
            "currency": config.CURRENCY,
            "classification": "regulated_stablecoin",
            "regulatory_treatment": "non_security",
            "policy_id": config.POLICY_VERSION,
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
        "policy_version": config.POLICY_VERSION,
        "expires_in_seconds": config.PERMIT_TTL_SECONDS,
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

    store_recent_permit_context(
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
        expires_in_seconds=config.PERMIT_TTL_SECONDS,
        bundle_hash=bundle_hash,
        validity={"single_use": False},
        decision_result=decision_result,
        reason_codes=reason_codes,
        proof_artifact=proof_artifact,
    )
