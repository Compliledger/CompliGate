from __future__ import annotations

from fastapi import HTTPException

from app.core import config
from app.core.logging import get_logger

try:
    from xrpl.transaction import submit_and_wait
    from xrpl.wallet import Wallet

    _XRPL_SDK_AVAILABLE = True
except ImportError:
    _XRPL_SDK_AVAILABLE = False
    submit_and_wait = None

logger = get_logger("main")


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
    if config.XRPL_SIGNING_SEED:
        return "xrpl_signing_seed"
    if config.XRPL_DEMO_WALLET_SEED and config.XRPL_NETWORK.lower() != "mainnet":
        return "xrpl_demo_wallet_seed"
    return "unconfigured"


def sign_payment_transaction(payment, client):
    if submit_and_wait is None:
        raise HTTPException(
            status_code=400,
            detail={"error": "xrpl_sdk_unavailable", "reason": "xrpl-py SDK is not installed"},
        )

    wallet = get_signing_wallet()
    if wallet is None:
        raise HTTPException(
            status_code=400,
            detail={"error": "signing_wallet_not_configured", "reason": "XRPL_SIGNING_SEED is not configured"},
        )

    try:
        payment.account = wallet.address
    except Exception:
        raise HTTPException(
            status_code=500,
            detail={"error": "xrpl_payment_build_failed", "reason": "Unable to apply signing account"},
        )

    try:
        return submit_and_wait(payment, client, wallet)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": "xrpl_submit_failed", "reason": str(exc)},
        ) from exc
