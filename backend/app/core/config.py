from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()

_TRUE_VALUES = ("true", "1", "yes")


def _get_bool(name: str, default: str) -> bool:
    return os.getenv(name, default).strip().lower() in _TRUE_VALUES


def _get_int(name: str, default: str) -> int:
    return int(os.getenv(name, default))


def _get_csv(name: str, default: str) -> list[str]:
    value = os.getenv(name, default)
    return [item.strip() for item in value.split(",") if item.strip()]


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
    DATABASE_URL: str
    AUTH_API_KEYS: list[str]
    XRPL_SIGNING_SEED: str


def _build_settings() -> Settings:
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
        DATABASE_URL=os.getenv("DATABASE_URL", "").strip(),
        AUTH_API_KEYS=_get_csv("AUTH_API_KEYS", ""),
        XRPL_SIGNING_SEED=os.getenv("XRPL_SIGNING_SEED", "").strip(),
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
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
AUTH_API_KEYS = _get_csv("AUTH_API_KEYS", "")
XRPL_SIGNING_SEED = os.getenv("XRPL_SIGNING_SEED", "").strip()
