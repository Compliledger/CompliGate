from __future__ import annotations

import time
from decimal import Decimal, InvalidOperation

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core import config
from app.core.auth import require_request_auth
from app.core.logging import get_logger
from app.models.permit import PermitRequest
from app.models.proof import build_proof_artifact
from app.services.permit_service import create_permit
from app.services.storage_service import save_proof_artifact
from app.services.xrpl_service import (
    encode_memo_text,
    extract_bundle_hash_from_tx,
    fetch_xrpl_transaction,
    get_xrpl_client,
    resolve_signer,
)

try:
    from xrpl.models.transactions import Memo, Payment
    from xrpl.transaction import submit_and_wait
    from xrpl.utils import xrp_to_drops

    _XRPL_SDK_AVAILABLE = True
except ImportError:
    _XRPL_SDK_AVAILABLE = False
    Memo = None
    Payment = None
    submit_and_wait = None
    xrp_to_drops = None

logger = get_logger("main")

router = APIRouter(dependencies=[Depends(require_request_auth)])

_XRPL_TESTNET_GENESIS = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"


class RoundtripRequest(BaseModel):
    destination: str = Field(
        default=_XRPL_TESTNET_GENESIS,
        description=(
            "XRPL destination address. Defaults to the well-known testnet "
            "genesis account so the roundtrip works out of the box."
        ),
    )
    amount_xrp: float = Field(
        default=0.001,
        description="XRP amount to send. Minimum meaningful value is 0.000001 (1 drop). Default: 0.001.",
    )


@router.post("/v1/demo/roundtrip")
def demo_roundtrip(req: RoundtripRequest):
    """
    Complete CompliGate → XRPL testnet roundtrip in a single call.

    Steps executed in order:
      1. Resolve the configured XRPL signer wallet.
      2. Issue a compliance permit (subject = signer wallet address).
      3. Submit a real XRPL testnet Payment with bundle_hash encoded in the first memo.
      4. Fetch the transaction back from the XRPL node by tx_hash.
      5. Decode the memo from the fetched transaction.
      6. Confirm decoded memo == bundle_hash.
      7. Build and return a signed proof artifact.

    Decision is SETTLED_COMPLIANT only when the transaction is validated on-ledger
    and the decoded memo exactly matches the bundle_hash.

    Requires XRPL_DEMO_WALLET_SEED or XRPL_SIGNER_SEED to be set.
    """
    if not _XRPL_SDK_AVAILABLE or Payment is None or Memo is None or submit_and_wait is None or xrp_to_drops is None:
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

    signer = resolve_signer()
    if signer.wallet is None:
        raise HTTPException(
            status_code=400,
            detail=signer.error or {
                "error": "signing_wallet_not_configured",
                "reason": "Set XRPL_DEMO_WALLET_SEED or XRPL_SIGNER_SEED to enable the roundtrip.",
            },
        )

    wallet = signer.wallet
    subject = wallet.address

    logger.info("roundtrip_start subject=%s destination=%s amount_xrp=%s", subject, req.destination, req.amount_xrp)

    # Step 1 — Issue the compliance permit (demo providers pass for any clean address).
    permit_req = PermitRequest(subject=subject, action="transfer", amount=req.amount_xrp)
    permit = create_permit(permit_req)
    bundle_hash = permit.bundle_hash

    logger.info("roundtrip_permit_issued bundle_hash=%s decision=%s", bundle_hash, permit.decision_result)

    # Step 2 — Build and submit the XRPL Payment with bundle_hash in the memo.
    try:
        drops = xrp_to_drops(Decimal(str(req.amount_xrp)))
    except (InvalidOperation, Exception) as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_amount", "reason": str(exc)},
        ) from exc

    memos = [
        Memo(
            memo_data=encode_memo_text(bundle_hash),
            memo_type=encode_memo_text("text/plain"),
        )
    ]
    payment = Payment(
        account=wallet.address,
        destination=req.destination,
        amount=drops,
        memos=memos,
    )

    try:
        response = submit_and_wait(payment, client, wallet)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": "xrpl_submit_failed", "reason": str(exc)},
        ) from exc

    result_payload = response.result if hasattr(response, "result") else {}
    meta = result_payload.get("meta", {}) if isinstance(result_payload, dict) else {}
    if not isinstance(meta, dict):
        meta = {}

    engine_result = meta.get("TransactionResult", "unknown")
    tx_hash = result_payload.get("hash", "") if isinstance(result_payload, dict) else ""
    ledger_index_raw = result_payload.get("ledger_index") if isinstance(result_payload, dict) else None
    ledger_index = ledger_index_raw if isinstance(ledger_index_raw, int) else None

    logger.info(
        "roundtrip_tx_submitted tx_hash=%s engine_result=%s ledger_index=%s",
        tx_hash, engine_result, ledger_index,
    )

    if not tx_hash:
        raise HTTPException(
            status_code=502,
            detail={"error": "xrpl_no_tx_hash", "reason": "XRPL node did not return a transaction hash."},
        )

    # Step 3 — Fetch the transaction back from XRPL to confirm it is on-ledger.
    tx_data = fetch_xrpl_transaction(tx_hash)

    # submit_and_wait already returns the validated result; also pull from the
    # re-fetched payload so both paths agree.
    tx_validated = bool(
        result_payload.get("validated", False) or tx_data.get("validated", False)
    )
    if ledger_index is None:
        ledger_index = tx_data.get("ledger_index") or tx_data.get("inLedger")

    # Step 4 — Decode the memo from the fetched transaction.
    decoded_memo = extract_bundle_hash_from_tx(tx_data)
    if decoded_memo is None:
        nested = tx_data.get("tx") or tx_data.get("tx_json") or {}
        if isinstance(nested, dict):
            decoded_memo = extract_bundle_hash_from_tx(nested)

    # Step 5 — Confirm decoded memo exactly matches the bundle_hash.
    memo_match = decoded_memo == bundle_hash

    # Step 6 — Determine settlement decision.
    compliant = tx_validated and memo_match
    decision = "SETTLED_COMPLIANT" if compliant else "SETTLEMENT_NON_COMPLIANT"

    reason_codes: list[str] = ["PERMIT_CONTEXT_FOUND"]
    if tx_validated:
        reason_codes.append("XRPL_TX_VALIDATED")
    else:
        reason_codes.append("XRPL_TX_NOT_VALIDATED")
    if memo_match:
        reason_codes.append("BUNDLE_HASH_MEMO_MATCHED")
    else:
        reason_codes.append("BUNDLE_HASH_MEMO_MISMATCH")
    reason_codes.append(decision)

    now = int(time.time())
    anchor_metadata: dict = {
        "network": config.XRPL_NETWORK,
        "tx_hash": tx_hash,
        "verified_at": now,
    }
    if ledger_index is not None:
        anchor_metadata["ledger_index"] = ledger_index

    proof_artifact = build_proof_artifact(
        module="CompliGate",
        entity_id=tx_hash,
        rule_version_used=config.POLICY_VERSION,
        decision_result=decision,
        evaluation_context={
            "subject": subject,
            "bundle_hash": bundle_hash,
            "tx_hash": tx_hash,
            "ledger_index": ledger_index,
            "validated": tx_validated,
            "decoded_memo": decoded_memo,
            "memo_match": memo_match,
            "engine_result": engine_result,
            "signer_address": wallet.address,
            "destination": req.destination,
            "xrpl_network": config.XRPL_NETWORK,
            "permit_decision": permit.decision_result,
        },
        reason_codes=reason_codes,
        timestamp=now,
        bundle_hash=bundle_hash,
        anchor_metadata=anchor_metadata,
    )

    save_proof_artifact(
        bundle_hash=bundle_hash,
        artifact=proof_artifact,
        artifact_type="demo_roundtrip",
    )

    logger.info(
        "roundtrip_complete subject=%s bundle_hash=%s tx_hash=%s validated=%s memo_match=%s decision=%s",
        subject, bundle_hash, tx_hash, tx_validated, memo_match, decision,
    )

    return {
        "permit": {
            "subject": subject,
            "bundle_hash": bundle_hash,
            "signature": permit.signature,
            "decision_result": permit.decision_result,
            "reason_codes": permit.reason_codes,
            "expires_at": permit.expires_at,
        },
        "xrpl_tx": {
            "tx_hash": tx_hash,
            "ledger_index": ledger_index,
            "validated": tx_validated,
            "engine_result": engine_result,
            "network": config.XRPL_NETWORK,
            "from_address": wallet.address,
            "to_address": req.destination,
            "amount_xrp": str(req.amount_xrp),
        },
        "memo_verification": {
            "bundle_hash": bundle_hash,
            "decoded_memo": decoded_memo,
            "match": memo_match,
        },
        "settlement": {
            "decision": decision,
            "reason_codes": reason_codes,
            "proof_artifact": proof_artifact.model_dump(),
        },
    }
