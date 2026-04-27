from __future__ import annotations

import time
from decimal import Decimal, InvalidOperation

import requests as http_requests
from fastapi import HTTPException

from app.core import config
from app.core.logging import get_logger
from app.models.xrpl import XRPLPaymentRequest
from app.services.xrpl_signer_service import is_signing_configured, sign_payment_transaction

try:
    from xrpl.clients import JsonRpcClient
    from xrpl.models.amounts import IssuedCurrencyAmount
    from xrpl.models.requests import AccountInfo, AccountLines, ServerInfo, Tx
    from xrpl.models.transactions import Memo, Payment
    from xrpl.transaction import autofill_and_sign, submit_and_wait
    from xrpl.utils import xrp_to_drops
    from xrpl.wallet import Wallet

    _XRPL_SDK_AVAILABLE = True
except ImportError:
    _XRPL_SDK_AVAILABLE = False
    IssuedCurrencyAmount = None
    Memo = None
    Payment = None
    ServerInfo = None
    autofill_and_sign = None
    submit_and_wait = None
    xrp_to_drops = None
    Wallet = None  # type: ignore[assignment]
    Wallet = None

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
    if Payment is None or Memo is None or xrp_to_drops is None or submit_and_wait is None:
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

    # ``amount`` is an XRP amount (e.g. "1" = 1 XRP). Convert via the SDK
    # helper to the drops integer string the XRPL Payment requires.
    try:
        xrp_amount = Decimal(str(req.amount))
    except (InvalidOperation, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_amount", "reason": f"Invalid XRP amount: {req.amount!r}"},
        ) from exc

    try:
        drops = xrp_to_drops(xrp_amount)
    except Exception as exc:  # XRPRangeException etc.
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_amount", "reason": str(exc)},
        ) from exc

    memos = None
    if req.memo_bundle_hash:
        memos = [
            Memo(
                memo_data=req.memo_bundle_hash.encode("utf-8").hex(),
                memo_type="text/plain".encode("utf-8").hex(),
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
    meta = result_payload.get("meta") if isinstance(result_payload, dict) else {}
    if not isinstance(meta, dict):
        meta = {}
    engine_result = meta.get("TransactionResult", "unknown")
    tx_hash = result_payload.get("hash", "") if isinstance(result_payload, dict) else ""
    validated = bool(result_payload.get("validated", False)) if isinstance(result_payload, dict) else False
    ledger_index = result_payload.get("ledger_index") if isinstance(result_payload, dict) else None
    if not isinstance(ledger_index, int):
        ledger_index = None

    amount_value = str(req.amount)

    logger.info(
        "xrpl_payment_submitted tx_hash=%s destination=%s amount_xrp=%s drops=%s engine_result=%s validated=%s",
        tx_hash,
        req.destination,
        amount_value,
        drops,
        engine_result,
        validated,
    )

    result: dict = {
        "submitted": True,
        "tx_hash": tx_hash,
        "engine_result": engine_result,
        "validated": validated,
        "ledger_index": ledger_index,
        "network": "testnet",
        "asset": "XRP",
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


# ---------------------------------------------------------------------------
# Real XRPL testnet client surface
#
# The functions below provide a minimal, explicit interface around the XRPL
# JSON-RPC endpoint configured via ``XRPL_RPC_URL``. They intentionally:
#
#   * never fabricate a transaction hash,
#   * never return mock / placeholder responses, and
#   * always perform a real JSON-RPC call against the configured node.
#
# When the RPC endpoint is not reachable, the SDK is missing, or the node
# returns an error, these functions return a structured error dict of the
# shape ``{"error": <code>, "reason": <human readable>}`` instead of raising,
# so callers can surface the failure without leaking exceptions.
# ---------------------------------------------------------------------------


def _xrpl_error(code: str, reason: str) -> dict:
    return {"error": code, "reason": reason}


def get_client() -> "JsonRpcClient | None":
    """Return a real ``JsonRpcClient`` bound to ``XRPL_RPC_URL``.

    Returns ``None`` when the xrpl-py SDK is unavailable or the RPC URL is
    not configured. Callers should treat ``None`` as "RPC unavailable" and
    surface a structured error to the user.
    """
    if not _XRPL_SDK_AVAILABLE:
        logger.warning("xrpl-py SDK is not installed – XRPL client unavailable")
        return None
    if not config.XRPL_RPC_URL:
        logger.warning("XRPL_RPC_URL is not configured – XRPL client unavailable")
        return None
    return JsonRpcClient(config.XRPL_RPC_URL)


def get_network_status() -> dict:
    """Query the XRPL node's ``server_info`` and return a structured snapshot.

    Performs a real JSON-RPC call. Returns a structured error dict if the
    RPC endpoint is unavailable or the request fails.
    """
    client = get_client()
    if client is None:
        return _xrpl_error(
            "xrpl_not_configured",
            "XRPL client is not available (SDK missing or XRPL_RPC_URL unset)",
        )
    if ServerInfo is None:  # pragma: no cover - guarded by SDK availability
        return _xrpl_error("xrpl_sdk_unavailable", "xrpl-py SDK is not installed")

    try:
        response = client.request(ServerInfo())
    except Exception as exc:
        logger.error("get_network_status failed: %s", exc)
        return _xrpl_error("xrpl_rpc_failed", str(exc))

    if not response.is_successful():
        return _xrpl_error(
            "xrpl_rpc_error",
            str(response.result.get("error_message") or response.result.get("error") or "unknown"),
        )

    info = response.result.get("info", {}) or {}
    validated_ledger = info.get("validated_ledger", {}) or {}
    return {
        "network": config.XRPL_NETWORK,
        "rpc_url": config.XRPL_RPC_URL,
        "server_state": info.get("server_state"),
        "build_version": info.get("build_version"),
        "complete_ledgers": info.get("complete_ledgers"),
        "validated_ledger_index": validated_ledger.get("seq"),
        "validated_ledger_hash": validated_ledger.get("hash"),
        "peers": info.get("peers"),
        "uptime": info.get("uptime"),
    }


def submit_payment(
    destination: str,
    amount: "str | dict | IssuedCurrencyAmount",
    *,
    wallet: "Wallet | None" = None,
    memo_bundle_hash: str | None = None,
    destination_tag: int | None = None,
) -> dict:
    """Sign and submit a real XRPL Payment transaction.

    ``amount`` may be a drop string (XRP), a dict matching the XRPL issued
    currency amount shape, or an :class:`IssuedCurrencyAmount` instance.

    Returns a dict containing the real ``tx_hash`` returned by the XRPL node
    along with the engine result and validated flag. On failure a structured
    error dict is returned – never a fabricated hash.
    """
    if not _XRPL_SDK_AVAILABLE or Payment is None or submit_and_wait is None:
        return _xrpl_error("xrpl_sdk_unavailable", "xrpl-py SDK is not installed")

    client = get_client()
    if client is None:
        return _xrpl_error(
            "xrpl_not_configured",
            "XRPL client is not available (SDK missing or XRPL_RPC_URL unset)",
        )

    if wallet is None:
        signer = resolve_signer()
        if signer.wallet is None:
            return signer.error or _xrpl_error(
                "signing_wallet_not_configured",
                "XRPL signer wallet is not configured",
            )
        wallet = signer.wallet

    # Normalize ``amount`` into the form xrpl-py expects: either a string of
    # drops for XRP or an IssuedCurrencyAmount for issued currencies.
    payment_amount: "str | IssuedCurrencyAmount"
    if isinstance(amount, dict):
        if IssuedCurrencyAmount is None:  # pragma: no cover - guarded above
            return _xrpl_error("xrpl_sdk_unavailable", "xrpl-py SDK is not installed")
        try:
            payment_amount = IssuedCurrencyAmount(
                currency=amount["currency"],
                issuer=amount["issuer"],
                value=str(amount["value"]),
            )
        except KeyError as exc:
            return _xrpl_error(
                "invalid_amount",
                f"missing required amount field: {exc.args[0]}",
            )
    else:
        payment_amount = amount  # str (drops) or IssuedCurrencyAmount

    memos = None
    if memo_bundle_hash and Memo is not None:
        memos = [
            Memo(
                memo_data=memo_bundle_hash.encode("utf-8").hex(),
                memo_type="text/plain".encode("utf-8").hex(),
            )
        ]

    try:
        payment = Payment(
            account=wallet.address,
            destination=destination,
            amount=payment_amount,
            destination_tag=destination_tag,
            memos=memos,
        )
    except Exception as exc:
        logger.error("submit_payment build failed: %s", exc)
        return _xrpl_error("invalid_payment", str(exc))

    try:
        response = submit_and_wait(payment, client, wallet)
    except Exception as exc:
        logger.error("submit_payment submit failed: %s", exc)
        return _xrpl_error("xrpl_submit_failed", str(exc))

    result = response.result or {}
    tx_hash = result.get("hash") or ""
    if not tx_hash:
        return _xrpl_error(
            "xrpl_submit_no_hash",
            "XRPL node did not return a transaction hash",
        )

    meta = result.get("meta", {})
    engine_result = meta.get("TransactionResult", "unknown") if isinstance(meta, dict) else "unknown"

    logger.info(
        "submit_payment tx_hash=%s destination=%s engine_result=%s",
        tx_hash,
        destination,
        engine_result,
    )

    return {
        "submitted": True,
        "tx_hash": tx_hash,
        "engine_result": engine_result,
        "validated": bool(result.get("validated", False)),
        "network": config.XRPL_NETWORK,
        "destination": destination,
    }


def fetch_transaction(tx_hash: str) -> dict:
    """Fetch a transaction from the XRPL node using a real ``tx`` JSON-RPC call.

    Returns the raw ``result`` dict from the node on success, or a
    structured error dict on failure. Never returns mock data.
    """
    if not tx_hash:
        return _xrpl_error("invalid_tx_hash", "tx_hash must be a non-empty string")

    client = get_client()
    if client is None:
        return _xrpl_error(
            "xrpl_not_configured",
            "XRPL client is not available (SDK missing or XRPL_RPC_URL unset)",
        )

    try:
        response = client.request(Tx(transaction=tx_hash))
    except Exception as exc:
        logger.error("fetch_transaction failed for %s: %s", tx_hash, exc)
        return _xrpl_error("xrpl_rpc_failed", str(exc))

    result = response.result or {}
    if not response.is_successful():
        return _xrpl_error(
            "xrpl_rpc_error",
            str(result.get("error_message") or result.get("error") or "unknown"),
        )
    return result


def wait_for_validated_tx(tx_hash: str, timeout_seconds: int = 20) -> dict:
    """Poll the XRPL node until ``tx_hash`` is validated or ``timeout_seconds``
    elapses.

    Returns the validated transaction ``result`` dict on success. On
    timeout or RPC failure a structured error dict is returned.
    """
    if not tx_hash:
        return _xrpl_error("invalid_tx_hash", "tx_hash must be a non-empty string")
    if timeout_seconds <= 0:
        return _xrpl_error(
            "invalid_timeout",
            "timeout_seconds must be a positive integer",
        )

    deadline = time.monotonic() + timeout_seconds
    poll_interval = 1.0
    last_result: dict | None = None

    while True:
        result = fetch_transaction(tx_hash)
        last_result = result

        # Distinguish "not found yet" (transient) from terminal RPC errors.
        if "error" in result:
            err = result["error"]
            transient = err == "xrpl_rpc_failed" or (
                err == "xrpl_rpc_error"
                and "txnNotFound" in (result.get("reason") or "")
            )
            if not transient:
                return result
        elif result.get("validated"):
            return result

        if time.monotonic() >= deadline:
            return _xrpl_error(
                "xrpl_tx_not_validated",
                f"Transaction {tx_hash} was not validated within {timeout_seconds}s",
            )

        time.sleep(min(poll_interval, max(0.1, deadline - time.monotonic())))
        poll_interval = min(poll_interval * 1.5, 4.0)


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
