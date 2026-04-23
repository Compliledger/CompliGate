"""External compliance provider abstraction layer.

This package defines vendor-neutral interfaces for the external compliance
signals CompliGate relies on (sanctions screening, KYC / identity status,
reserve / liquidity evidence). Concrete provider integrations are intentionally
not wired in this layer; this module only exposes the abstractions and a
"not configured" implementation that fails closed by default.
"""

from app.services.providers.base import (
    PROVIDER_NOT_CONFIGURED_REASON,
    ProviderDecision,
    ProviderError,
    ProviderNotConfiguredError,
    ProviderResult,
    ProviderStatus,
)
from app.services.providers.kyc_provider import (
    KycProvider,
    NotConfiguredKycProvider,
)
from app.services.providers.reserve_provider import (
    NotConfiguredReserveProvider,
    ReserveProvider,
)
from app.services.providers.sanctions_provider import (
    NotConfiguredSanctionsProvider,
    SanctionsProvider,
)

__all__ = [
    "PROVIDER_NOT_CONFIGURED_REASON",
    "ProviderDecision",
    "ProviderError",
    "ProviderNotConfiguredError",
    "ProviderResult",
    "ProviderStatus",
    "SanctionsProvider",
    "NotConfiguredSanctionsProvider",
    "KycProvider",
    "NotConfiguredKycProvider",
    "ReserveProvider",
    "NotConfiguredReserveProvider",
]
