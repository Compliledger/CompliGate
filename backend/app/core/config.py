from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()

_TRUE_VALUES = ("true", "1", "yes")
_DEFAULT_API_KEY_HEADER_NAME = "X-API-Key"

# Supported XRPL signing modes.
# - "seed":     local seed-based signing (suitable for dev / staging only)
# - "disabled": signing is intentionally turned off; payment endpoints must
#               return a structured error rather than attempting to sign
# - "external": placeholder for a future HSM / custody signer integration;
#               not implemented yet, payment endpoints must return a
#               structured "not implemented" error
XRPL_SIGNING_MODES = ("seed", "disabled", "external")
_DEFAULT_XRPL_SIGNING_MODE = "seed"


def _get_bool(name: str, default: str) -> bool:
    return os.getenv(name, default).strip().lower() in _TRUE_VALUES


def _get_int(name: str, default: str) -> int:
    return int(os.getenv(name, default))


def _get_csv(name: str, default: str) -> list[str]:
    value = os.getenv(name, default)
    return [item.strip() for item in value.split(",") if item.strip()]


def _get_api_keys() -> list[str]:
    api_keys = _get_csv("API_KEYS", "")
    if api_keys:
        return api_keys
    return _get_csv("AUTH_API_KEYS", "")


def _get_api_key_header_name() -> str:
    return os.getenv("API_KEY_HEADER_NAME", _DEFAULT_API_KEY_HEADER_NAME).strip() or _DEFAULT_API_KEY_HEADER_NAME


def _get_xrpl_signing_mode() -> str:
    raw = os.getenv("XRPL_SIGNING_MODE", _DEFAULT_XRPL_SIGNING_MODE).strip().lower()
    if raw not in XRPL_SIGNING_MODES:
        return _DEFAULT_XRPL_SIGNING_MODE
    return raw


@dataclass(frozen=True)
class Settings:
    POLICY_VERSION: str
    JURISDICTION: str
    CURRENCY: str
    ISSUER_ADDRESS: str
    COMPLIGATE_PRIVATE_KEY_B64: str
    CORS_ORIGINS: list[str]
    XRPL_RPC_URL: str
    XRPL_NETWORK: str
    RLUSD_ISSUER: str
    RLUSD_CURRENCY: str
    XRPL_DEMO_WALLET_SEED: str
    XRPL_ENFORCE_RLUSD_ONLY: bool
    XRPL_REQUIRE_TRUSTLINE: bool
    PERMIT_TTL_SECONDS: int
    PERMIT_CONTEXT_CACHE_MAX_ITEMS: int
    API_KEY_ENABLED: bool
    API_KEY_HEADER_NAME: str
    API_KEYS: list[str]
    DATABASE_URL: str
    AUTH_API_KEYS: list[str]
    XRPL_SIGNING_SEED: str
    XRPL_SIGNING_MODE: str
    XRPL_SIGNER_ADDRESS: str
    XRPL_SIGNER_SEED: str
    XRPL_SIGNING_ENABLED: bool
    KYC_PROVIDER: str
    KYC_PROVIDER_URL: str
    KYC_PROVIDER_API_KEY: str
    KYC_API_KEY: str
    KYC_UPSTREAM_ASSERTION_SECRET: str
    KYC_UPSTREAM_ASSERTION_TRUSTED_ISSUERS: list[str]
    SANCTIONS_PROVIDER: str
    SANCTIONS_PROVIDER_URL: str
    SANCTIONS_PROVIDER_API_KEY: str
    SANCTIONS_API_KEY: str
    RESERVE_PROVIDER: str
    RESERVE_PROVIDER_URL: str
    RESERVE_PROVIDER_API_KEY: str
    RESERVE_API_KEY: str
    RESERVE_ATTESTATION_SECRET: str
    RESERVE_ATTESTATION_TRUSTED_ATTESTORS: list[str]
    FAIL_CLOSED_COMPLIANCE: bool


def _get_provider_api_key(short_name: str, legacy_name: str) -> str:
    """Return the configured API key for a compliance provider.

    The short ``*_API_KEY`` form (e.g. ``KYC_API_KEY``) is preferred. The
    longer historical ``*_PROVIDER_API_KEY`` form is accepted as a
    backward-compatible fallback so existing deployments keep working.
    """
    short = os.getenv(short_name, "").strip()
    if short:
        return short
    return os.getenv(legacy_name, "").strip()


def _build_settings() -> Settings:
    api_keys = _get_api_keys()
    kyc_api_key = _get_provider_api_key("KYC_API_KEY", "KYC_PROVIDER_API_KEY")
    sanctions_api_key = _get_provider_api_key("SANCTIONS_API_KEY", "SANCTIONS_PROVIDER_API_KEY")
    reserve_api_key = _get_provider_api_key("RESERVE_API_KEY", "RESERVE_PROVIDER_API_KEY")

    return Settings(
        POLICY_VERSION=os.getenv("POLICY_VERSION", "RLUSD_US_v1"),
        JURISDICTION=os.getenv("JURISDICTION", "US"),
        CURRENCY=os.getenv("CURRENCY", "RLUSD"),
        ISSUER_ADDRESS=os.getenv("ISSUER_ADDRESS", "rEXAMPLE_ISSUER_ADDRESS"),
        COMPLIGATE_PRIVATE_KEY_B64=os.getenv("COMPLIGATE_PRIVATE_KEY_B64", "").strip(),
        CORS_ORIGINS=_get_csv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173"),
        XRPL_RPC_URL=os.getenv("XRPL_RPC_URL", "https://s.altnet.rippletest.net:51234"),
        XRPL_NETWORK=os.getenv("XRPL_NETWORK", "xrpl_testnet"),
        RLUSD_ISSUER=os.getenv("RLUSD_ISSUER", ""),
        RLUSD_CURRENCY=os.getenv("RLUSD_CURRENCY", "RLUSD"),
        XRPL_DEMO_WALLET_SEED=os.getenv("XRPL_DEMO_WALLET_SEED", ""),
        XRPL_ENFORCE_RLUSD_ONLY=_get_bool("XRPL_ENFORCE_RLUSD_ONLY", "false"),
        XRPL_REQUIRE_TRUSTLINE=_get_bool("XRPL_REQUIRE_TRUSTLINE", "false"),
        PERMIT_TTL_SECONDS=_get_int("PERMIT_TTL_SECONDS", "300"),
        PERMIT_CONTEXT_CACHE_MAX_ITEMS=_get_int("PERMIT_CONTEXT_CACHE_MAX_ITEMS", "1000"),
        API_KEY_ENABLED=_get_bool("API_KEY_ENABLED", "true"),
        API_KEY_HEADER_NAME=_get_api_key_header_name(),
        API_KEYS=api_keys,
        DATABASE_URL=os.getenv("DATABASE_URL", "").strip(),
        AUTH_API_KEYS=api_keys,
        XRPL_SIGNING_SEED=os.getenv("XRPL_SIGNING_SEED", "").strip(),
        XRPL_SIGNING_MODE=_get_xrpl_signing_mode(),
        XRPL_SIGNER_ADDRESS=os.getenv("XRPL_SIGNER_ADDRESS", "").strip(),
        XRPL_SIGNER_SEED=os.getenv("XRPL_SIGNER_SEED", "").strip(),
        XRPL_SIGNING_ENABLED=_get_bool("XRPL_SIGNING_ENABLED", "true"),
        KYC_PROVIDER=os.getenv("KYC_PROVIDER", "null").strip(),
        KYC_PROVIDER_URL=os.getenv("KYC_PROVIDER_URL", "").strip(),
        KYC_PROVIDER_API_KEY=kyc_api_key,
        KYC_API_KEY=kyc_api_key,
        KYC_UPSTREAM_ASSERTION_SECRET=os.getenv("KYC_UPSTREAM_ASSERTION_SECRET", "").strip(),
        KYC_UPSTREAM_ASSERTION_TRUSTED_ISSUERS=_get_csv("KYC_UPSTREAM_ASSERTION_TRUSTED_ISSUERS", ""),
        SANCTIONS_PROVIDER=os.getenv("SANCTIONS_PROVIDER", "null").strip(),
        SANCTIONS_PROVIDER_URL=os.getenv("SANCTIONS_PROVIDER_URL", "").strip(),
        SANCTIONS_PROVIDER_API_KEY=sanctions_api_key,
        SANCTIONS_API_KEY=sanctions_api_key,
        RESERVE_PROVIDER=os.getenv("RESERVE_PROVIDER", "null").strip(),
        RESERVE_PROVIDER_URL=os.getenv("RESERVE_PROVIDER_URL", "").strip(),
        RESERVE_PROVIDER_API_KEY=reserve_api_key,
        RESERVE_API_KEY=reserve_api_key,
        RESERVE_ATTESTATION_SECRET=os.getenv("RESERVE_ATTESTATION_SECRET", "").strip(),
        RESERVE_ATTESTATION_TRUSTED_ATTESTORS=_get_csv(
            "RESERVE_ATTESTATION_TRUSTED_ATTESTORS", ""
        ),
        FAIL_CLOSED_COMPLIANCE=_get_bool("FAIL_CLOSED_COMPLIANCE", "true"),
    )


settings = _build_settings()
APP_NAME = "CompliGate Backend"

POLICY_VERSION = os.getenv("POLICY_VERSION", "RLUSD_US_v1")
JURISDICTION = os.getenv("JURISDICTION", "US")
CURRENCY = os.getenv("CURRENCY", "RLUSD")
ISSUER_ADDRESS = os.getenv("ISSUER_ADDRESS", "rEXAMPLE_ISSUER_ADDRESS")
PRIVATE_KEY_B64 = os.getenv("COMPLIGATE_PRIVATE_KEY_B64", "").strip()
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173")

XRPL_RPC_URL = os.getenv("XRPL_RPC_URL", "https://s.altnet.rippletest.net:51234")
XRPL_NETWORK = os.getenv("XRPL_NETWORK", "xrpl_testnet")
RLUSD_ISSUER = os.getenv("RLUSD_ISSUER", "")
RLUSD_CURRENCY = os.getenv("RLUSD_CURRENCY", "RLUSD")
XRPL_DEMO_WALLET_SEED = os.getenv("XRPL_DEMO_WALLET_SEED", "")
XRPL_ENFORCE_RLUSD_ONLY = os.getenv("XRPL_ENFORCE_RLUSD_ONLY", "false").lower() in ("true", "1", "yes")
XRPL_REQUIRE_TRUSTLINE = os.getenv("XRPL_REQUIRE_TRUSTLINE", "false").lower() in ("true", "1", "yes")
PERMIT_TTL_SECONDS = int(os.getenv("PERMIT_TTL_SECONDS", "300"))
PERMIT_CONTEXT_CACHE_MAX_ITEMS = int(os.getenv("PERMIT_CONTEXT_CACHE_MAX_ITEMS", "1000"))
API_KEY_ENABLED = _get_bool("API_KEY_ENABLED", "true")
API_KEY_HEADER_NAME = _get_api_key_header_name()
API_KEYS = _get_api_keys()
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
AUTH_API_KEYS = API_KEYS
XRPL_SIGNING_SEED = os.getenv("XRPL_SIGNING_SEED", "").strip()
XRPL_SIGNING_MODE = _get_xrpl_signing_mode()
XRPL_SIGNER_ADDRESS = os.getenv("XRPL_SIGNER_ADDRESS", "").strip()
XRPL_SIGNER_SEED = os.getenv("XRPL_SIGNER_SEED", "").strip()
XRPL_SIGNING_ENABLED = _get_bool("XRPL_SIGNING_ENABLED", "true")

# --- Compliance providers ---
# Each check (KYC / sanctions / reserve) is delegated to a configured
# provider. Supported kinds:
#   null          - no provider configured; engine fails closed (default)
#   static_allow  - explicit, traceable approval for dev / tests only
#   http          - real third-party HTTPS endpoint (URL + API key required)
#
# API keys can be supplied via the short ``*_API_KEY`` form (preferred for
# real-provider integrations) or the historical ``*_PROVIDER_API_KEY``
# form, which is kept for backward compatibility.
KYC_PROVIDER = os.getenv("KYC_PROVIDER", "null").strip()
KYC_PROVIDER_URL = os.getenv("KYC_PROVIDER_URL", "").strip()
KYC_API_KEY = _get_provider_api_key("KYC_API_KEY", "KYC_PROVIDER_API_KEY")
KYC_PROVIDER_API_KEY = KYC_API_KEY
# Trusted upstream KYC assertion settings.
#
# When ``KYC_PROVIDER=upstream_assertion``, every permit request is
# expected to include an HMAC-signed ``kyc_assertion`` payload issued by
# one of the institutions listed in ``KYC_UPSTREAM_ASSERTION_TRUSTED_ISSUERS``
# (CSV) and signed with ``KYC_UPSTREAM_ASSERTION_SECRET``. Missing or
# invalid assertions return ``unavailable`` so the engine can fail
# closed under ``FAIL_CLOSED_COMPLIANCE``.
KYC_UPSTREAM_ASSERTION_SECRET = os.getenv("KYC_UPSTREAM_ASSERTION_SECRET", "").strip()
KYC_UPSTREAM_ASSERTION_TRUSTED_ISSUERS = _get_csv("KYC_UPSTREAM_ASSERTION_TRUSTED_ISSUERS", "")
SANCTIONS_PROVIDER = os.getenv("SANCTIONS_PROVIDER", "null").strip()
SANCTIONS_PROVIDER_URL = os.getenv("SANCTIONS_PROVIDER_URL", "").strip()
SANCTIONS_API_KEY = _get_provider_api_key("SANCTIONS_API_KEY", "SANCTIONS_PROVIDER_API_KEY")
SANCTIONS_PROVIDER_API_KEY = SANCTIONS_API_KEY
RESERVE_PROVIDER = os.getenv("RESERVE_PROVIDER", "null").strip()
RESERVE_PROVIDER_URL = os.getenv("RESERVE_PROVIDER_URL", "").strip()
RESERVE_API_KEY = _get_provider_api_key("RESERVE_API_KEY", "RESERVE_PROVIDER_API_KEY")
RESERVE_PROVIDER_API_KEY = RESERVE_API_KEY
# Trusted reserve / liquidity attestation settings.
#
# When ``RESERVE_PROVIDER=attestation``, every permit request is
# expected to include an HMAC-signed ``reserve_attestation`` payload
# issued by one of the attestors listed in
# ``RESERVE_ATTESTATION_TRUSTED_ATTESTORS`` (CSV) and signed with
# ``RESERVE_ATTESTATION_SECRET``. Missing or invalid attestations
# return ``unavailable`` so the engine can fail closed under
# ``FAIL_CLOSED_COMPLIANCE``.
RESERVE_ATTESTATION_SECRET = os.getenv("RESERVE_ATTESTATION_SECRET", "").strip()
RESERVE_ATTESTATION_TRUSTED_ATTESTORS = _get_csv(
    "RESERVE_ATTESTATION_TRUSTED_ATTESTORS", ""
)

# When true (the default), the compliance engine must deny rather than
# silently pass when a provider is missing or unavailable. Setting this
# to ``false`` is only intended for narrow local-development scenarios
# and is unsafe for any real deployment.
FAIL_CLOSED_COMPLIANCE = _get_bool("FAIL_CLOSED_COMPLIANCE", "true")
