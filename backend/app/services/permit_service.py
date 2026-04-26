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
from app.services.compliance.engine import derive_reserve_components
from app.services.policy_service import MAX_AMOUNT, evaluate_permit_policy, validate_subject
from app.services.proof_service import create_permit_proof_artifact
from app.services.storage_service import save_permit, save_proof_artifact, save_reserve_evidence
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
        kyc_assertion=req.kyc_assertion,
        reserve_attestation=req.reserve_attestation,
    )
    reason_codes = policy_result["reason_codes"]
    decision_result = policy_result["decision_result"]
    compliance = policy_result["compliance"]

    now = int(time.time())
    exp = now + config.PERMIT_TTL_SECONDS

    within_limit = req.amount <= MAX_AMOUNT if req.amount is not None else True

    kyc_status = compliance.status_for("kyc")
    sanctions_status = compliance.status_for("sanctions")

    # Decompose the reserve provider's evidence into separate
    # reserve-backing and liquidity attestations. When the provider
    # returns a single overall status the components fall back to that
    # status, so the bundle and proof artifact never invent fields that
    # were not derived from real provider evidence.
    reserve_evidence_item = next(
        (item for item in compliance.evidence if item.get("check") == "reserve"),
        None,
    )
    reserve_components = derive_reserve_components(reserve_evidence_item)
    reserve_component_status = reserve_components["reserve_status"]
    liquidity_component_status = reserve_components["liquidity_status"]
    reserve_component_reference = reserve_components["reserve_reference"]
    liquidity_component_reference = reserve_components["liquidity_reference"]

    # Build attestation references from real provider evidence rather
    # than synthetic random hashes. When a provider did not return a
    # reference (e.g. unavailable), the attestation is recorded as None
    # so the proof artifact never claims an attestation that doesn't
    # exist.
    reserve_reference = reserve_component_reference
    liquidity_reference = liquidity_component_reference
    kyc_reference = compliance.reference_for("kyc")
    sanctions_reference = compliance.reference_for("sanctions")

    # Surface the normalized KYC result (provider_name / source_system,
    # subject_id, kyc_status, jurisdiction, checked_at,
    # evidence_reference, reason_codes) as a first-class attestation so
    # downstream consumers never have to reach into compliance_evidence
    # to find it. Falls back to ``None`` when no KYC provider was wired
    # up so the bundle never fabricates a normalized result.
    kyc_evidence_item = next(
        (item for item in compliance.evidence if item.get("check") == "kyc"),
        None,
    )
    kyc_result_payload = None
    if kyc_evidence_item is not None:
        details = kyc_evidence_item.get("details") or {}
        if isinstance(details, dict) and isinstance(details.get("kyc_result"), dict):
            kyc_result_payload = details["kyc_result"]

    # Same treatment for the destination-side KYC evaluation when the
    # engine resolved it (transfer with a counterparty). Both the
    # provider-reported reference and the normalized KycResult are
    # surfaced as first-class attestations so the bundle and proof
    # artifact carry destination-side KYC evidence explicitly.
    kyc_destination_evidence_item = next(
        (
            item
            for item in compliance.evidence
            if item.get("check") == "kyc:destination"
        ),
        None,
    )
    kyc_destination_reference = None
    kyc_destination_result_payload = None
    if kyc_destination_evidence_item is not None:
        kyc_destination_reference = kyc_destination_evidence_item.get("reference")
        details = kyc_destination_evidence_item.get("details") or {}
        if isinstance(details, dict) and isinstance(details.get("kyc_result"), dict):
            kyc_destination_result_payload = details["kyc_result"]

    # Surface the normalized ReserveResult (provider_name /
    # attestor_name, reserve_status, liquidity_status, checked_at,
    # evidence_reference, reason_codes) as a first-class attestation so
    # the bundle and proof artifact carry the per-dimension reserve and
    # liquidity outcome explicitly. Falls back to ``None`` when no
    # reserve provider was wired up so the bundle never fabricates a
    # normalized result.
    reserve_result_payload: dict | None = None
    if reserve_evidence_item is not None:
        details = reserve_evidence_item.get("details") or {}
        if isinstance(details, dict) and isinstance(details.get("reserve_result"), dict):
            reserve_result_payload = details["reserve_result"]

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
            # ``reserve_backed`` and ``liquidity_verified`` are derived
            # from the engine-normalized component statuses produced by
            # ``derive_reserve_components``. That helper already maps
            # missing / unavailable / denied evidence to a non-APPROVED
            # status, so ``_constraint_value_for`` only renders ``True``
            # when the provider explicitly returned an approved /
            # verified state — the bundle never claims a reserve or
            # liquidity check succeeded when it did not.
            "reserve_backed": _constraint_value_for(reserve_component_status),
            "liquidity_verified": _constraint_value_for(liquidity_component_status),
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
            "kyc_result": kyc_result_payload,
            "kyc_destination_reference": kyc_destination_reference,
            "kyc_destination_result": kyc_destination_result_payload,
            "reserve_reference": reserve_reference,
            "liquidity_reference": liquidity_reference,
            "reserve_result": reserve_result_payload,
            "sanctions_reference": sanctions_reference,
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
        "reserve_status": reserve_component_status.value,
        "liquidity_status": liquidity_component_status.value,
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

    # Persist the structured reserve / liquidity evidence as a first-class
    # record linked to this permit's bundle_hash. Uses the *real* provider
    # response (no random hashes, no hard-coded ``true``); when no reserve
    # evidence was produced the call is a no-op.
    save_reserve_evidence(
        bundle_hash=bundle_hash,
        evidence_item=reserve_evidence_item,
        asset=asset.get("currency", ""),
        issuer=asset.get("issuer", ""),
        db=db,
    )

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
