from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from app.core import config
from app.core.logging import get_logger

try:
    from xrpl.models.transactions import Payment
    from xrpl.transaction import submit_and_wait
    from xrpl.wallet import Wallet

    _XRPL_SDK_AVAILABLE = True
except ImportError:
    _XRPL_SDK_AVAILABLE = False
    Payment = None
    submit_and_wait = None

logger = get_logger("main")


# Signing modes returned by ``get_signing_mode``.
SIGNING_MODE_PRODUCTION = "xrpl_signing_seed"
SIGNING_MODE_DEMO = "xrpl_demo_wallet_seed"
SIGNING_MODE_UNCONFIGURED = "unconfigured"
SIGNING_MODE_DISABLED = "disabled"


def is_signing_available() -> bool:
    """Return ``True`` when the xrpl-py SDK is importable.

    Used by callers (route handlers, health checks) that need to know
    whether signing can possibly be performed without touching wallet
    seed configuration directly.
    """
    return _XRPL_SDK_AVAILABLE


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


def get_signing_mode() -> str:
    if not _XRPL_SDK_AVAILABLE:
        return SIGNING_MODE_DISABLED
    if config.XRPL_SIGNING_SEED:
        return SIGNING_MODE_PRODUCTION
    if config.XRPL_DEMO_WALLET_SEED and config.XRPL_NETWORK.lower() != "mainnet":
        return SIGNING_MODE_DEMO
    return SIGNING_MODE_UNCONFIGURED


def is_signing_configured() -> bool:
    """Return ``True`` when a usable signing wallet is configured.

    This is the public surface used by health checks and route handlers
    so that no other module needs to read ``XRPL_SIGNING_SEED`` /
    ``XRPL_DEMO_WALLET_SEED`` directly.
    """
    return get_signing_mode() in (SIGNING_MODE_PRODUCTION, SIGNING_MODE_DEMO)


def get_signing_status() -> dict:
    """Return a structured signing status snapshot for diagnostics.

    The dict intentionally never contains seed material – only the
    derived signing mode and a boolean flag describing whether signing
    is currently available.
    """
    mode = get_signing_mode()
    return {
        "configured": mode in (SIGNING_MODE_PRODUCTION, SIGNING_MODE_DEMO),
        "mode": mode,
        "sdk_available": _XRPL_SDK_AVAILABLE,
    }


def sign_payment_transaction(
    *,
    client: Any,
    destination: str,
    amount: Any,
    memos: list[Any] | None = None,
) -> Any:
    if not _XRPL_SDK_AVAILABLE or submit_and_wait is None or Payment is None:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "signing_disabled",
                "reason": "xrpl-py SDK is not installed; XRPL signing is disabled",
            },
        )

    wallet = get_signing_wallet()
    if wallet is None:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "signer_not_configured",
                "reason": "XRPL signer wallet is not configured",
                "mode": get_signing_mode(),
            },
        )

    payment = Payment(
        account=wallet.address,
        destination=destination,
        amount=amount,
        memos=memos or None,
    )

    try:
        return submit_and_wait(payment, client, wallet)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": "xrpl_submit_failed", "reason": str(exc)},
        ) from exc
