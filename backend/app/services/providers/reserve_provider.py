"""Reserve / liquidity evidence provider abstraction."""

from __future__ import annotations

from abc import abstractmethod
from typing import Any, Mapping

from app.services.providers.base import (
    NotConfiguredProviderMixin,
    ProviderResult,
    _DomainProvider,
)


class ReserveProvider(_DomainProvider):
    """Vendor-neutral interface for reserve / liquidity evidence.

    Implementations attest that a regulated stablecoin issuer (or similar
    asset operator) holds sufficient reserves / liquidity to back the
    requested action. This typically wraps an attestation feed, a proof of
    reserves API, or an internal treasury system.
    """

    @abstractmethod
    def get_evidence(
        self,
        *,
        asset: str,
        amount: float | int | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> ProviderResult:
        """Return the current reserve / liquidity evidence for ``asset``.

        Args:
            asset: Asset identifier (e.g. currency code such as ``"RLUSD"``).
            amount: Optional notional amount the caller is about to act on,
                so the provider can decide whether available liquidity is
                sufficient.
            context: Optional structured context (issuer address,
                jurisdiction, settlement venue) the provider may use to
                refine the lookup. Implementations must treat unknown keys
                as opaque.

        Returns:
            A normalized :class:`ProviderResult`. Implementations must never
            raise for ordinary "insufficient reserves" outcomes; raise only
            for true transport / configuration errors.
        """


class NotConfiguredReserveProvider(NotConfiguredProviderMixin, ReserveProvider):
    """Default reserve provider used when no concrete vendor is wired up.

    Fails closed (``decision=DENY``, ``status=NOT_CONFIGURED``) unless the
    ``ALLOW_UNCONFIGURED_PROVIDERS`` environment flag is set, in which case
    it returns an ``ALLOW`` / ``SKIPPED`` result for local development.
    """

    provider_name = "reserve:not_configured"
    domain_reason_prefix = "RESERVE"

    def is_configured(self) -> bool:
        return False

    def get_evidence(
        self,
        *,
        asset: str,
        amount: float | int | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> ProviderResult:
        metadata: dict[str, Any] = {"asset": asset, "amount": amount}
        if context:
            metadata["context_keys"] = sorted(context.keys())
        return self._not_configured_result(extra_metadata=metadata)
