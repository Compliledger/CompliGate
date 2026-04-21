from __future__ import annotations

import requests as http_requests
from fastapi import HTTPException

from app.core import config
from app.core.logging import get_logger
from app.models.xrpl import XRPLPaymentRequest
from app.services.xrpl_signer_service import is_signing_configured, sign_payment_transaction

try:
    from xrpl.clients import JsonRpcClient
    from xrpl.models.amounts import IssuedCurrencyAmount
    from xrpl.models.requests import AccountInfo, AccountLines, Tx
    from xrpl.models.transactions import Memo
    from xrpl.wallet import Wallet

    _XRPL_SDK_AVAILABLE = True
except ImportError:
    _XRPL_SDK_AVAILABLE = False
    IssuedCurrencyAmount = None
    Memo = None
    Wallet = None  # type: ignore[assignment]

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
    """Return a signing Wallet for the configured ``XRPL_SIGNING_MODE``.

    Returns ``None`` when no wallet is available for any reason (signing
    disabled, unsupported mode, missing seed, invalid seed, or the xrpl-py
    SDK not being installed). Callers are responsible for translating that
    into a structured error response; use :func:`resolve_signer` for richer
    diagnostics.
    """
    signer = resolve_signer()
    return signer.wallet


class SignerResolution:
    """Outcome of resolving the configured XRPL signer.

    ``wallet`` is set only for modes that produce a usable local wallet
    (currently only ``seed``). ``error`` describes why a wallet could not
    be produced and is intended for use in HTTP error responses.
    """

    __slots__ = ("mode", "wallet", "error")

    def __init__(
        self,
        mode: str,
        wallet: "Wallet | None" = None,
        error: dict | None = None,
    ) -> None:
        self.mode = mode
        self.wallet = wallet
        self.error = error


def _signer_error(code: str, reason: str, *, mode: str) -> dict:
    return {"error": code, "reason": reason, "signing_mode": mode}


def resolve_signer() -> SignerResolution:
    """Resolve the configured XRPL signer without raising.

    This is the single place where signing-mode policy is enforced so that
    local seed signing is no longer hardcoded into the payment flow.
    """
    mode = (config.XRPL_SIGNING_MODE or "seed").lower()

    if not config.XRPL_SIGNING_ENABLED:
        return SignerResolution(
            mode=mode,
            error=_signer_error(
                "xrpl_signing_disabled",
                "XRPL signing is disabled (XRPL_SIGNING_ENABLED=false)",
                mode=mode,
            ),
        )

    if mode == "disabled":
        return SignerResolution(
            mode=mode,
            error=_signer_error(
                "xrpl_signing_disabled",
                "XRPL signing is disabled (XRPL_SIGNING_MODE=disabled)",
                mode=mode,
            ),
        )

    if mode == "external":
        # Placeholder for a future HSM / custody signer integration. The
        # interface is intentionally not implemented yet.
        return SignerResolution(
            mode=mode,
            error=_signer_error(
                "xrpl_signer_not_implemented",
                "External XRPL signer integration is not implemented yet",
                mode=mode,
            ),
        )

    if mode != "seed":
        return SignerResolution(
            mode=mode,
            error=_signer_error(
                "xrpl_signing_mode_unsupported",
                f"Unsupported XRPL signing mode: {mode!r}",
                mode=mode,
            ),
        )

    # mode == "seed"
    if not _XRPL_SDK_AVAILABLE:
        logger.warning("xrpl-py SDK is not installed – signing wallet unavailable")
        return SignerResolution(
            mode=mode,
            error=_signer_error(
                "xrpl_sdk_unavailable",
                "xrpl-py SDK is not installed",
                mode=mode,
            ),
        )

    seed = config.XRPL_SIGNER_SEED or config.XRPL_SIGNING_SEED
    if seed:
        try:
            wallet = Wallet.from_seed(seed)
        except Exception:
            logger.error("invalid_xrpl_signer_seed")
            return SignerResolution(
                mode=mode,
                error=_signer_error(
                    "xrpl_signer_seed_invalid",
                    "Configured XRPL signer seed is invalid",
                    mode=mode,
                ),
            )
        if config.XRPL_SIGNER_ADDRESS and wallet.address != config.XRPL_SIGNER_ADDRESS:
            logger.error(
                "xrpl_signer_address_mismatch expected=%s actual=%s",
                config.XRPL_SIGNER_ADDRESS,
                wallet.address,
            )
            return SignerResolution(
                mode=mode,
                error=_signer_error(
                    "xrpl_signer_address_mismatch",
                    "Configured XRPL_SIGNER_ADDRESS does not match the seed-derived address",
                    mode=mode,
                ),
            )
        return SignerResolution(mode=mode, wallet=wallet)

    if config.XRPL_DEMO_WALLET_SEED:
        if config.XRPL_NETWORK.lower() == "mainnet":
            logger.error("demo_seed_refused_on_mainnet")
            return SignerResolution(
                mode=mode,
                error=_signer_error(
                    "xrpl_demo_seed_refused_on_mainnet",
                    "Demo wallet seed cannot be used on mainnet",
                    mode=mode,
                ),
            )
        logger.warning("xrpl_signer_seed_not_set_falling_back_to_demo_seed")
        try:
            wallet = Wallet.from_seed(config.XRPL_DEMO_WALLET_SEED)
        except Exception:
            logger.error("invalid_xrpl_demo_wallet_seed")
            return SignerResolution(
                mode=mode,
                error=_signer_error(
                    "xrpl_demo_seed_invalid",
                    "Configured XRPL demo wallet seed is invalid",
                    mode=mode,
                ),
            )
        return SignerResolution(mode=mode, wallet=wallet)

    return SignerResolution(
        mode=mode,
        error=_signer_error(
            "xrpl_signer_seed_not_configured",
            "XRPL_SIGNER_SEED is not configured",
            mode=mode,
        ),
    )


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
    # `signer_configured` reports only whether a signer credential is present,
    # never the seed itself, so it is safe for operational visibility.
    signer_configured = bool(config.XRPL_SIGNER_SEED or config.XRPL_SIGNING_SEED)
    demo_wallet_configured = is_signing_configured()
    if not rpc_url:
        return {
            "configured": False,
            "reachable": False,
            "network": config.XRPL_NETWORK,
            "rlusd_configured": rlusd_configured,
            "demo_wallet_configured": demo_wallet_configured,
            "signing_mode": config.XRPL_SIGNING_MODE,
            "signing_enabled": config.XRPL_SIGNING_ENABLED,
            "signer_configured": signer_configured,
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
        "signing_mode": config.XRPL_SIGNING_MODE,
        "signing_enabled": config.XRPL_SIGNING_ENABLED,
        "signer_configured": signer_configured,
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
    if IssuedCurrencyAmount is None or Memo is None:
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
        error_detail = signer.error or {
            "error": "signing_wallet_not_configured",
            "reason": "XRPL signer is not available",
            "signing_mode": signer.mode,
        }
        status_code = 501 if error_detail.get("error") == "xrpl_signer_not_implemented" else 400
        raise HTTPException(status_code=status_code, detail=error_detail)
    wallet = signer.wallet

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

    response = sign_payment_transaction(
        client=client,
        destination=req.destination,
        amount=payment_amount,
        memos=memos,
        wallet=wallet,
    )

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
