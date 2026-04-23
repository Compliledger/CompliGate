"""Sanctions / watchlist screening provider abstraction."""

from __future__ import annotations

from abc import abstractmethod
from typing import Any, Mapping

from app.services.providers.base import (
    NotConfiguredProviderMixin,
    ProviderResult,
    _DomainProvider,
)


class SanctionsProvider(_DomainProvider):
    """Vendor-neutral interface for sanctions / watchlist screening.

    Implementations screen a subject (typically an XRPL classic address or a
    legal-entity identifier) against one or more sanctions lists (e.g.
    OFAC SDN, EU consolidated, UN) and return a normalized
    :class:`ProviderResult`.
    """

    @abstractmethod
    def screen(
        self,
        *,
        subject: str,
        context: Mapping[str, Any] | None = None,
    ) -> ProviderResult:
        """Screen ``subject`` against the provider's sanctions data.

        Args:
            subject: The identifier being screened (XRPL address, LEI, name).
            context: Optional structured context (jurisdiction, asset code,
                counterparty hints, etc.) the provider may use to refine the
                screen. Implementations must treat unknown keys as opaque.

        Returns:
            A normalized :class:`ProviderResult`. Implementations must never
            raise for ordinary deny / hit outcomes; raise only for true
            transport / configuration errors.
        """


class NotConfiguredSanctionsProvider(NotConfiguredProviderMixin, SanctionsProvider):
    """Default sanctions provider used when no concrete vendor is wired up.

    Fails closed (``decision=DENY``, ``status=NOT_CONFIGURED``) unless the
    ``ALLOW_UNCONFIGURED_PROVIDERS`` environment flag is set, in which case
    it returns an ``ALLOW`` / ``SKIPPED`` result for local development.
    """

    provider_name = "sanctions:not_configured"
    domain_reason_prefix = "SANCTIONS"

    def is_configured(self) -> bool:
        return False

    def screen(
        self,
        *,
        subject: str,
        context: Mapping[str, Any] | None = None,
    ) -> ProviderResult:
        metadata: dict[str, Any] = {"subject": subject}
        if context:
            metadata["context_keys"] = sorted(context.keys())
        return self._not_configured_result(extra_metadata=metadata)
