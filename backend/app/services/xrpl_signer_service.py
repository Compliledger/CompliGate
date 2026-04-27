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


# ---------------------------------------------------------------------------
# XRPL_SIGNER_SEED-based signing (new public surface).
#
# These helpers implement the documented contract: load the seed strictly
# from ``XRPL_SIGNER_SEED``, build an xrpl-py ``Wallet`` from it, and
# expose a minimal, seed-free health snapshot for diagnostics. The seed
# is never logged, returned, or echoed in error payloads.
# ---------------------------------------------------------------------------


def _signer_signing_mode() -> str:
    """Return the configured high-level signing mode (``seed``/``disabled``/...).

    This wraps ``config.XRPL_SIGNING_MODE`` so tests / callers don't need
    to know the default. It is distinct from the legacy
    ``get_signing_mode()`` above which describes which seed source the
    legacy helpers picked.
    """
    return (config.XRPL_SIGNING_MODE or "seed").lower()


def _signing_enabled() -> bool:
    """Whether seed-based signing is currently enabled.

    Signing is considered enabled only when:
    * the xrpl-py SDK is importable,
    * the operator has not turned signing off via ``XRPL_SIGNING_ENABLED=false``,
    * the configured ``XRPL_SIGNING_MODE`` is ``seed`` (the only mode this
      service can actually perform).
    """
    if not _XRPL_SDK_AVAILABLE:
        return False
    if not config.XRPL_SIGNING_ENABLED:
        return False
    return _signer_signing_mode() == "seed"


def _seed_missing_error(mode: str) -> dict:
    """Structured error payload for the "signing enabled but seed missing" case.

    Intentionally contains no seed material and no other configuration
    secrets – only the diagnostic ``signing_mode`` so callers can render
    a useful HTTP error.
    """
    return {
        "error": "xrpl_signer_seed_not_configured",
        "reason": "XRPL_SIGNER_SEED is not configured",
        "signing_mode": mode,
    }


def get_wallet() -> "Wallet | None":
    """Return an xrpl-py ``Wallet`` built from ``XRPL_SIGNER_SEED``.

    Returns ``None`` when signing is disabled, the SDK is unavailable,
    the seed is not configured, or the seed cannot be parsed. The seed
    itself is never logged or included in the return value; only the
    derived wallet (which exposes the public address) is returned.
    """
    if not _signing_enabled():
        return None

    seed = config.XRPL_SIGNER_SEED
    if not seed:
        return None

    try:
        return Wallet.from_seed(seed)
    except Exception:
        # Deliberately log a static message – never the seed value.
        logger.error("invalid_xrpl_signer_seed")
        return None


def get_signer_health() -> dict:
    """Return a seed-free health snapshot for the XRPL signer.

    The returned dict always contains exactly these keys:

    * ``signing_enabled``  – whether seed-based signing is currently active
    * ``signing_mode``     – configured signing mode (``seed``/``disabled``/...)
    * ``signer_configured``– whether ``XRPL_SIGNER_SEED`` is set *and* parses
    * ``signer_address``   – the seed-derived classic address, or the
      configured ``XRPL_SIGNER_ADDRESS`` fallback, or ``None``

    The seed itself is never read into, logged from, or returned by this
    function.
    """
    mode = _signer_signing_mode()
    enabled = _signing_enabled()

    signer_address: str | None = config.XRPL_SIGNER_ADDRESS or None
    signer_configured = False

    if _XRPL_SDK_AVAILABLE and config.XRPL_SIGNER_SEED:
        try:
            wallet = Wallet.from_seed(config.XRPL_SIGNER_SEED)
        except Exception:
            logger.error("invalid_xrpl_signer_seed")
        else:
            signer_configured = True
            signer_address = wallet.address

    return {
        "signing_enabled": enabled,
        "signing_mode": mode,
        "signer_configured": signer_configured,
        "signer_address": signer_address,
    }


def get_signer_error() -> dict | None:
    """Return a structured error if signing is enabled but unusable.

    Returns ``None`` when signing is disabled (no error to report) or
    when a usable signer wallet is configured. Returns the same payload
    shape as :func:`_seed_missing_error` when signing is enabled but no
    valid ``XRPL_SIGNER_SEED`` is available.
    """
    if not _signing_enabled():
        return None
    if get_wallet() is not None:
        return None
    return _seed_missing_error(_signer_signing_mode())


def sign_payment_transaction(
    *,
    client: Any,
    destination: str,
    amount: Any,
    memos: list[Any] | None = None,
    wallet: "Wallet | None" = None,
) -> Any:
    if not _XRPL_SDK_AVAILABLE or submit_and_wait is None or Payment is None:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "signing_disabled",
                "reason": "xrpl-py SDK is not installed; XRPL signing is disabled",
            },
        )

    if wallet is None:
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
