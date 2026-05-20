from __future__ import annotations

import re
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


def encode_memo_text(text: str) -> str:
    """Encode UTF-8 text into the hex string XRPL memos require.

    XRPL ``MemoData``/``MemoType``/``MemoFormat`` fields must be hex-encoded
    strings. This helper centralises the encoding so callers do not repeat
    ``text.encode("utf-8").hex()`` everywhere.
    """
    if text is None:
        raise TypeError("encode_memo_text requires a string, got None")
    return text.encode("utf-8").hex()


def decode_memo_hex(hex_str: str | None) -> str:
    """Decode an XRPL memo hex string back into UTF-8 text.

    Returns an empty string when ``hex_str`` is missing/empty so callers can
    treat absent memos uniformly. Falls back to returning the original hex
    string when the value is not valid hex or is not valid UTF-8.
    """
    if not hex_str:
        return ""
    try:
        return bytes.fromhex(hex_str).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return hex_str


def extract_bundle_hash_from_tx(tx_payload: dict) -> str | None:
    """Return the decoded ``bundle_hash`` from the first memo of ``tx_payload``.

    Returns ``None`` when the transaction has no memos, the first memo has no
    ``MemoData`` field, or the payload is not a dict – callers receive a
    consistent ``None`` for the "no memo" case.
    """
    if not isinstance(tx_payload, dict):
        return None
    memos_raw = tx_payload.get("Memos")
    if not memos_raw or not isinstance(memos_raw, list):
        return None
    first_memo = memos_raw[0]
    memo_obj = first_memo.get("Memo", first_memo) if isinstance(first_memo, dict) else {}
    if not isinstance(memo_obj, dict):
        return None
    memo_data_hex = memo_obj.get("MemoData")
    if not memo_data_hex:
        return None
    decoded = decode_memo_hex(memo_data_hex)
    return decoded or None


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

    bundle_hash = extract_bundle_hash_from_tx(tx_data)

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
        "bundle_hash": bundle_hash,
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

    # On testnet the signing wallet typically holds only a small XRP balance
    # (the faucet funds accounts with 10 XRP). Cap the payment at 1 XRP so
    # demo flows never exceed the available balance regardless of what RLUSD
    # amount was written in the permit.
    _TESTNET_XRP_CAP = Decimal("1")
    _is_testnet = config.XRPL_NETWORK.lower() in ("testnet", "xrpl_testnet", "altnet")
    testnet_amount_capped = False
    if _is_testnet and xrp_amount > _TESTNET_XRP_CAP:
        logger.info(
            "xrpl_payment_amount_capped original=%s cap=%s network=%s",
            xrp_amount, _TESTNET_XRP_CAP, config.XRPL_NETWORK,
        )
        xrp_amount = _TESTNET_XRP_CAP
        testnet_amount_capped = True

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
                memo_data=encode_memo_text(req.memo_bundle_hash),
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
        exc_str = str(exc)
        # Detect deterministic XRPL engine failure codes (tec/ter/tef/tem).
        # These are not server errors — return 422 so callers can distinguish
        # a ledger-level business rejection from a real network/infra failure.
        _engine_match = re.search(r'\b(tec[A-Z_]+|ter[A-Z_]+|tef[A-Z_]+|tem[A-Z_]+)\b', exc_str)
        _engine_code = _engine_match.group(1) if _engine_match else None
        _status = 422 if _engine_code else 502
        raise HTTPException(
            status_code=_status,
            detail={
                "error": "xrpl_submit_failed",
                "reason": exc_str,
                "source_account": wallet.address,
                "network": config.XRPL_NETWORK,
                "engine_result": _engine_code or "unknown",
            },
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
        "network": config.XRPL_NETWORK,
        "asset": "XRP",
        "currency": "XRP",
        "issuer": "",
        "amount": str(xrp_amount),
        "destination": req.destination,
        "testnet_amount_capped": testnet_amount_capped,
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
                memo_data=encode_memo_text(memo_bundle_hash),
                memo_type=encode_memo_text("text/plain"),
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


def _decode_memos(memos_raw: object) -> list[dict]:
    """Return a list of decoded XRPL memo dicts.

    Each entry has ``type``, ``format`` and ``data`` keys with their
    hex-encoded values decoded back to UTF-8 (falling back to the original
    hex string when the value is not valid UTF-8 hex). Returns an empty
    list when ``memos_raw`` is missing or malformed so callers can iterate
    unconditionally.
    """
    if not isinstance(memos_raw, list):
        return []
    decoded: list[dict] = []
    for entry in memos_raw:
        memo_obj = entry.get("Memo", entry) if isinstance(entry, dict) else {}
        if not isinstance(memo_obj, dict):
            continue
        decoded.append(
            {
                "type": decode_memo_hex(memo_obj.get("MemoType")),
                "format": decode_memo_hex(memo_obj.get("MemoFormat")),
                "data": decode_memo_hex(memo_obj.get("MemoData")),
            }
        )
    return decoded


def _tx_not_found_error(tx_hash: str, result: dict) -> dict:
    reason = (
        result.get("error_message")
        or result.get("error")
        or f"Transaction {tx_hash} was not found on the XRPL node"
    )
    return {
        "found": False,
        "tx_hash": tx_hash,
        "error": "tx_not_found",
        "reason": str(reason),
    }


def fetch_transaction(tx_hash: str) -> dict:
    """Fetch a transaction from the XRPL node using a real ``tx`` JSON-RPC call.

    Performs a real ``Tx`` request via the configured ``xrpl-py`` JSON-RPC
    client (no mocks). On success returns a structured dict with the
    fields most callers need:

    * ``found``        -- ``True`` when the node returned a transaction
    * ``tx_hash``      -- the hash that was requested
    * ``validated``    -- whether the tx is in a validated ledger
    * ``ledger_index`` -- the ledger sequence the tx was included in
    * ``account``/``source`` -- the originating account (``source`` is an
      alias for ``account`` for callers that prefer that wording)
    * ``destination``  -- the ``Destination`` field, when present
    * ``amount``       -- normalized via :func:`normalize_xrpl_amount`
    * ``memos``        -- list of ``{type, format, data}`` decoded from hex
    * ``raw``          -- the raw, JSON-safe ``result`` dict from the node

    When the transaction is not found, a structured error of the shape
    ``{"found": False, "tx_hash": ..., "error": "tx_not_found",
    "reason": ...}`` is returned. RPC / configuration failures return
    ``{"found": False, "error": <code>, "reason": ...}``.
    """
    if not tx_hash:
        return {
            "found": False,
            "tx_hash": tx_hash or "",
            "error": "invalid_tx_hash",
            "reason": "tx_hash must be a non-empty string",
        }

    client = get_client()
    if client is None:
        return {
            "found": False,
            "tx_hash": tx_hash,
            "error": "xrpl_not_configured",
            "reason": "XRPL client is not available (SDK missing or XRPL_RPC_URL unset)",
        }

    try:
        response = client.request(Tx(transaction=tx_hash))
    except Exception as exc:
        logger.error("fetch_transaction failed for %s: %s", tx_hash, exc)
        return {
            "found": False,
            "tx_hash": tx_hash,
            "error": "xrpl_rpc_failed",
            "reason": str(exc),
        }

    result = response.result or {}

    if not response.is_successful():
        # ``txnNotFound`` is the canonical "tx does not exist (yet)" code
        # from rippled. Surface it as a structured not-found result so
        # callers (and pollers) can distinguish it from real RPC errors.
        err_code = str(result.get("error") or "")
        if err_code == "txnNotFound":
            return _tx_not_found_error(tx_hash, result)
        return {
            "found": False,
            "tx_hash": tx_hash,
            "error": "xrpl_rpc_error",
            "reason": str(
                result.get("error_message") or result.get("error") or "unknown"
            ),
        }

    # xrpl-py exposes the transaction fields either at the top level of
    # ``result`` (legacy API shape) or under a nested ``tx_json`` (newer
    # rippled / clio responses). Prefer ``tx_json`` when present and fall
    # back to the top-level dict so this works against both shapes.
    tx_json = result.get("tx_json")
    tx_payload = tx_json if isinstance(tx_json, dict) else result

    account = tx_payload.get("Account", "")
    destination = tx_payload.get("Destination", "")
    amount_raw = tx_payload.get("Amount")

    return {
        "found": True,
        "tx_hash": result.get("hash") or tx_payload.get("hash") or tx_hash,
        "validated": bool(result.get("validated", False)),
        "ledger_index": result.get("ledger_index")
        or tx_payload.get("ledger_index"),
        "account": account,
        "source": account,
        "destination": destination,
        "amount": normalize_xrpl_amount(amount_raw) if amount_raw is not None else None,
        "memos": _decode_memos(tx_payload.get("Memos")),
        "raw": result,
    }


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
            transient = err in ("xrpl_rpc_failed", "tx_not_found")
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
