from __future__ import annotations

import requests as http_requests
from fastapi import HTTPException

from app.core import config
from app.core.logging import get_logger
from app.models.xrpl import XRPLPaymentRequest

try:
    from xrpl.clients import JsonRpcClient
    from xrpl.models.amounts import IssuedCurrencyAmount
    from xrpl.models.requests import AccountInfo, AccountLines, Tx
    from xrpl.models.transactions import Memo, Payment
    from xrpl.transaction import submit_and_wait
    from xrpl.wallet import Wallet

    _XRPL_SDK_AVAILABLE = True
except ImportError:
    _XRPL_SDK_AVAILABLE = False
    IssuedCurrencyAmount = None
    Memo = None
    Payment = None
    submit_and_wait = None

logger = get_logger("main")


def get_xrpl_client() -> "JsonRpcClient | None":
    if not _XRPL_SDK_AVAILABLE:
        logger.warning("xrpl-py SDK is not installed – XRPL client unavailable")
        return None
    if not config.XRPL_RPC_URL:
        logger.warning("XRPL_RPC_URL is not configured – XRPL client unavailable")
        return None
    return JsonRpcClient(config.XRPL_RPC_URL)


def get_demo_wallet() -> "Wallet | None":
    if not _XRPL_SDK_AVAILABLE:
        logger.warning("xrpl-py SDK is not installed – demo wallet unavailable")
        return None
    if not config.XRPL_DEMO_WALLET_SEED:
        logger.info("XRPL_DEMO_WALLET_SEED is not configured – demo wallet unavailable")
        return None
    return Wallet.from_seed(config.XRPL_DEMO_WALLET_SEED)


def get_signing_wallet() -> "Wallet | None":
    if not _XRPL_SDK_AVAILABLE:
        logger.warning("xrpl-py SDK is not installed – signing wallet unavailable")
        return None
    if config.XRPL_SIGNING_SEED:
        try:
            return Wallet.from_seed(config.XRPL_SIGNING_SEED)
        except Exception:
            logger.error("invalid_xrpl_signing_seed")
            return None
    if config.XRPL_DEMO_WALLET_SEED:
        if config.XRPL_NETWORK.lower() == "mainnet":
            logger.error("demo_seed_refused_on_mainnet")
            return None
        logger.warning("xrpl_signing_seed_not_set_falling_back_to_demo_seed")
        try:
            return Wallet.from_seed(config.XRPL_DEMO_WALLET_SEED)
        except Exception:
            logger.error("invalid_xrpl_demo_wallet_seed")
            return None
    return None


def get_account_info(address: str) -> dict:
    client = get_xrpl_client()
    if client is None:
        return {"error": "xrpl_not_configured", "reason": "XRPL client is not available"}
    try:
        response = client.request(AccountInfo(account=address))
        return response.result
    except Exception as exc:
        logger.error("get_account_info failed for %s: %s", address, exc)
        return {"error": "xrpl_request_failed", "reason": str(exc)}


def get_account_lines(address: str) -> dict:
    client = get_xrpl_client()
    if client is None:
        return {"error": "xrpl_not_configured", "reason": "XRPL client is not available"}
    try:
        response = client.request(AccountLines(account=address))
        return response.result
    except Exception as exc:
        logger.error("get_account_lines failed for %s: %s", address, exc)
        return {"error": "xrpl_request_failed", "reason": str(exc)}


def get_transaction(tx_hash: str) -> dict:
    client = get_xrpl_client()
    if client is None:
        return {"error": "xrpl_not_configured", "reason": "XRPL client is not available"}
    try:
        response = client.request(Tx(transaction=tx_hash))
        return response.result
    except Exception as exc:
        logger.error("get_transaction failed for %s: %s", tx_hash, exc)
        return {"error": "xrpl_request_failed", "reason": str(exc)}


def fetch_xrpl_transaction(tx_hash: str) -> dict:
    payload = {
        "method": "tx",
        "params": [{"transaction": tx_hash, "binary": False}],
    }
    try:
        resp = http_requests.post(config.XRPL_RPC_URL, json=payload, timeout=10)
        resp.raise_for_status()
        result = resp.json()
        if "result" in result:
            return result["result"]
        return result
    except http_requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": "xrpl_rpc_failed", "reason": str(exc)},
        ) from exc


def fetch_account_lines(address: str) -> list[dict]:
    payload = {
        "method": "account_lines",
        "params": [{"account": address}],
    }
    try:
        resp = http_requests.post(config.XRPL_RPC_URL, json=payload, timeout=10)
        resp.raise_for_status()
        result = resp.json()
        if "result" in result:
            return result["result"].get("lines", [])
        return result.get("lines", [])
    except http_requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": "xrpl_rpc_failed", "reason": str(exc)},
        ) from exc


def get_xrpl_health_status() -> dict:
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


def lookup_xrpl_transaction(tx_hash: str) -> dict:
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


def submit_xrpl_payment(req: XRPLPaymentRequest) -> dict:
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

    wallet = get_signing_wallet()
    if wallet is None:
        raise HTTPException(
            status_code=400,
            detail={"error": "signing_wallet_not_configured", "reason": "XRPL_SIGNING_SEED is not configured"},
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
        result["proof_link"] = {
            "bundle_hash": req.memo_bundle_hash,
            "tx_hash": tx_hash,
        }

    return result


def normalize_xrpl_amount(amount_obj: str | dict) -> dict:
    if isinstance(amount_obj, dict):
        return {
            "currency": amount_obj.get("currency", ""),
            "value": amount_obj.get("value", "0"),
            "issuer": amount_obj.get("issuer", ""),
        }
    try:
        drops = int(amount_obj)
    except (ValueError, TypeError):
        drops = 0
    return {
        "currency": "XRP",
        "value": str(drops / 1_000_000),
        "issuer": "",
    }


def normalize_amount(value: str | dict) -> dict:
    return normalize_xrpl_amount(value)


def is_rlusd_payment(tx_json: dict) -> bool:
    if tx_json.get("TransactionType") != "Payment":
        return False

    amount = tx_json.get("Amount", {})
    normalized = normalize_xrpl_amount(amount)

    if normalized["currency"] != config.RLUSD_CURRENCY:
        return False

    if config.RLUSD_ISSUER and normalized["issuer"] != config.RLUSD_ISSUER:
        return False

    return True
