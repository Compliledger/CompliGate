from __future__ import annotations

import base64
import time

from fastapi import APIRouter, Depends, HTTPException

from app.core.auth import require_request_auth
from app.core import config
from app.core.logging import get_logger
from app.core.security import VERIFY_KEY
from app.models.proof import build_proof_artifact
from app.models.xrpl import SettlementVerifyByHashRequest, SettlementVerifyByHashResponse, SettlementVerifyRequest
from app.services.settlement_service import fetch_xrpl_transaction, verify_settlement_against_permit, verify_settlement_by_hash as verify_settlement_by_hash_service
from app.services.storage_service import save_proof_artifact
from app.utils.canonical_json import canonical_json
from app.utils.hashing import proof_hash

router = APIRouter(dependencies=[Depends(require_request_auth)])
logger = get_logger("main")


@router.post("/v1/settle/verify")
def verify_settlement(req: SettlementVerifyRequest):
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

    tx_data = fetch_xrpl_transaction(req.tx_hash)
    result = verify_settlement_against_permit(tx_data, req.bundle)

    bundle_hash = proof_hash(req.bundle)

    expired = not not_expired

    decision_result = "SETTLED_COMPLIANT" if result["settlement_verified"] else "SETTLEMENT_NON_COMPLIANT"

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
        rule_version_used=config.POLICY_VERSION,
        decision_result=decision_result,
        evaluation_context=evaluation_context,
        reason_codes=reason_codes,
        timestamp=now,
        bundle_hash=bundle_hash,
        anchor_metadata={
            "network": config.XRPL_NETWORK,
            "tx_hash": req.tx_hash,
            "rpc_url_present": bool(config.XRPL_RPC_URL),
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
    save_proof_artifact(bundle_hash=bundle_hash, artifact=proof_artifact, artifact_type="settlement_verify")

    return {
        "settlement_verified": result["settlement_verified"],
        "permit_valid": signature_valid,
        "permit_expired": expired,
        "tx_hash": req.tx_hash,
        "bundle_hash": bundle_hash,
        "network": config.XRPL_NETWORK,
        "checks": result["checks"],
        "details": result["details"],
        "verified_at": now,
        "proof_artifact": proof_artifact.model_dump(),
    }


@router.post("/v1/settlement/verify", response_model=SettlementVerifyByHashResponse)
def verify_settlement_by_hash(req: SettlementVerifyByHashRequest):
    result = verify_settlement_by_hash_service(req.bundle_hash, req.tx_hash)
    save_proof_artifact(bundle_hash=req.bundle_hash, artifact=result.proof_artifact, artifact_type="settlement_verify_by_hash")
    logger.info(
        "settlement_verify tx_hash=%s bundle_hash=%s decision=%s",
        req.tx_hash,
        req.bundle_hash,
        result.decision_result,
    )
    return result
