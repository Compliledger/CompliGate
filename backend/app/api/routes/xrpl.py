from __future__ import annotations

import requests as http_requests
from fastapi import APIRouter, HTTPException

from app.core import config
from app.core.logging import get_logger
from app.models.xrpl import TrustlineCheckRequest, XRPLPaymentRequest, XRPLPaymentResponse
from app.services.settlement_service import build_proof_link, fetch_xrpl_transaction
from app.services.trustline_service import check_rlusd_trustline, fetch_account_lines, validate_trustline
from app.services.xrpl_service import get_demo_wallet, get_xrpl_client, normalize_xrpl_amount

try:
    from xrpl.models.amounts import IssuedCurrencyAmount
    from xrpl.models.transactions import Memo, Payment
    from xrpl.transaction import submit_and_wait
except ImportError:
    IssuedCurrencyAmount = None
    Memo = None
    Payment = None
    submit_and_wait = None

router = APIRouter()
logger = get_logger("main")


@router.get("/v1/xrpl/health")
def xrpl_health():
    rpc_url = config.XRPL_RPC_URL
    rlusd_configured = bool(config.RLUSD_ISSUER and config.RLUSD_CURRENCY)
    demo_wallet_configured = bool(config.XRPL_DEMO_WALLET_SEED)
    if not rpc_url:
        return {
            "configured": False,
            "reachable": False,
            "network": config.XRPL_NETWORK,
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
        "network": config.XRPL_NETWORK,
        "rlusd_configured": rlusd_configured,
        "demo_wallet_configured": demo_wallet_configured,
    }


@router.get("/v1/xrpl/tx/{tx_hash}")
def xrpl_tx_lookup(tx_hash: str):
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
        "network": config.XRPL_NETWORK,
        "raw": tx_data,
    }


@router.get("/v1/xrpl/account/{address}/trustlines")
def xrpl_account_trustlines(address: str):
    if not config.XRPL_RPC_URL:
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
        "network": config.XRPL_NETWORK,
        "trustline_count": len(lines),
        "rlusd_trustline": rlusd_check,
        "lines": lines,
    }


@router.post("/v1/xrpl/trustline/check")
def xrpl_trustline_check(req: TrustlineCheckRequest):
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
    if not config.XRPL_RPC_URL:
        raise HTTPException(
            status_code=400,
            detail={"error": "xrpl_not_configured", "reason": "XRPL_RPC_URL is not configured"},
        )

    result = validate_trustline(address, config.RLUSD_ISSUER, config.RLUSD_CURRENCY)
    result["address"] = address
    return result


@router.post("/v1/xrpl/payment", response_model=XRPLPaymentResponse)
def xrpl_payment(req: XRPLPaymentRequest):
    if submit_and_wait is None or IssuedCurrencyAmount is None or Memo is None or Payment is None:
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

    if config.XRPL_REQUIRE_TRUSTLINE:
        trustline_result = validate_trustline(req.destination, config.RLUSD_ISSUER, config.RLUSD_CURRENCY)
        if not trustline_result.get("trustline_exists", False):
            reason_codes = ["TRUSTLINE_REQUIRED", "TRUSTLINE_NOT_SATISFIED"]
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "trustline_required",
                    "reason": "destination must have trustline for configured RLUSD issuer/currency",
                    "reason_codes": reason_codes,
                    "destination": req.destination,
                    "issuer": config.RLUSD_ISSUER,
                    "currency": config.RLUSD_CURRENCY,
                    "raw_lines_checked": trustline_result.get("raw_lines_checked", 0),
                },
            )

    amount_value = str(req.amount)

    currency_code = config.RLUSD_CURRENCY
    if len(currency_code) > 3:
        currency_code = currency_code.encode("ascii").hex().upper().ljust(40, "0")

    payment_amount = IssuedCurrencyAmount(
        currency=currency_code,
        issuer=config.RLUSD_ISSUER,
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
        "network": config.XRPL_NETWORK,
        "currency": config.RLUSD_CURRENCY,
        "issuer": config.RLUSD_ISSUER,
        "amount": amount_value,
        "destination": req.destination,
    }

    if req.memo_bundle_hash:
        result["proof_link"] = build_proof_link(req.memo_bundle_hash, tx_hash)

    return result
