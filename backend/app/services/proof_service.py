from __future__ import annotations

import os
import time

from app.core import config
from app.core.logging import get_logger
from app.models.proof import ProofArtifact, build_proof_artifact
from app.services.policy_service import REASON_CODES, validate_action, validate_amount, validate_subject
from app.utils.hashing import proof_hash

logger = get_logger("main")


def random_hex(n_bytes: int = 32) -> str:
    return "0x" + os.urandom(n_bytes).hex()


def enrich_proof_artifact_with_anchor(
    proof_artifact: ProofArtifact,
    anchor_metadata: dict,
) -> ProofArtifact:
    return proof_artifact.model_copy(update={"anchor_metadata": anchor_metadata})


def create_proof_artifact_from_permit_req(req) -> ProofArtifact:
    validate_subject(req.subject)
    validate_action(req.action)
    validate_amount(req.amount)

    now = int(time.time())

    evaluation_context = {
        "action": req.action,
        "jurisdiction": config.JURISDICTION,
        "currency": config.CURRENCY,
        "issuer": config.ISSUER_ADDRESS,
        "amount": req.amount,
        "counterparty": req.counterparty,
    }

    core = {
        "module": config.APP_NAME,
        "entity_id": req.subject,
        "rule_version_used": config.POLICY_VERSION,
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
        config.POLICY_VERSION,
        artifact_hash,
    )
    return build_proof_artifact(**core, bundle_hash=artifact_hash)


def create_permit_proof_artifact(
    *,
    bundle: dict,
    reason_codes: list[str],
    timestamp: int,
    bundle_hash: str,
) -> ProofArtifact:
    return build_proof_artifact(
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
        timestamp=timestamp,
        bundle_hash=bundle_hash,
        anchor_metadata={},
    )
