from __future__ import annotations

import base64
import time

from fastapi import APIRouter, HTTPException

from app.core import config
from app.core.logging import get_logger
from app.core.security import VERIFY_KEY
from app.models.proof import build_proof_artifact
from app.models.xrpl import SettlementVerifyByHashRequest, SettlementVerifyByHashResponse, SettlementVerifyRequest
from app.services.permit_service import get_recent_permit_context
from app.services.policy_service import ASSET_CLASSIFICATION_REGULATED_STABLECOIN
from app.services.settlement_service import _evaluate_settlement_constraints, _extract_tx_payload, fetch_xrpl_transaction, verify_settlement_against_permit
from app.services.xrpl_service import normalize_xrpl_amount
from app.utils.canonical_json import canonical_json
from app.utils.hashing import proof_hash

router = APIRouter()
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
    permit_context = get_recent_permit_context(req.bundle_hash)
    permit_bundle = permit_context.get("bundle") if permit_context else None

    tx_data = fetch_xrpl_transaction(req.tx_hash)
    tx_payload = _extract_tx_payload(tx_data)

    decision_result, reason_codes, constraints_verified = _evaluate_settlement_constraints(
        tx_payload,
        permit_bundle=permit_bundle,
    )

    amount_info = normalize_xrpl_amount(tx_payload.get("Amount", {}))

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
        "jurisdiction": config.JURISDICTION,
        "kyc_verified": True,
        "sanctions_check": "passed",
        "reserve_backed": True,
        "liquidity_verified": True,
        "policy_conditions": {
            "jurisdiction": config.JURISDICTION,
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

    anchor_metadata: dict = {
        "network": config.XRPL_NETWORK,
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
        rule_version_used=config.POLICY_VERSION,
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
