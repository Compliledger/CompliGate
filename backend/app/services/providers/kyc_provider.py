"""KYC / identity status provider abstraction."""

from __future__ import annotations

from abc import abstractmethod
from typing import Any, Mapping

from app.services.providers.base import (
    NotConfiguredProviderMixin,
    ProviderResult,
    _DomainProvider,
)


class KycProvider(_DomainProvider):
    """Vendor-neutral interface for KYC / identity verification status.

    Implementations look up the current KYC / identity verification status
    of a subject (XRPL classic address, customer id, LEI, etc.) and
    translate the vendor-specific status into a normalized
    :class:`ProviderResult`.
    """

    @abstractmethod
    def get_status(
        self,
        *,
        subject: str,
        context: Mapping[str, Any] | None = None,
    ) -> ProviderResult:
        """Return the current KYC / identity status for ``subject``.

        Args:
            subject: Identifier of the participant whose KYC status is being
                requested.
            context: Optional structured context (jurisdiction, product,
                tier requirements) the provider may use to choose the
                appropriate KYC profile. Implementations must treat unknown
                keys as opaque.

        Returns:
            A normalized :class:`ProviderResult`. Implementations must never
            raise for ordinary "not verified" outcomes; raise only for true
            transport / configuration errors.
        """


class NotConfiguredKycProvider(NotConfiguredProviderMixin, KycProvider):
    """Default KYC provider used when no concrete vendor is wired up.

    Fails closed (``decision=DENY``, ``status=NOT_CONFIGURED``) unless the
    ``ALLOW_UNCONFIGURED_PROVIDERS`` environment flag is set, in which case
    it returns an ``ALLOW`` / ``SKIPPED`` result for local development.
    """

    provider_name = "kyc:not_configured"
    domain_reason_prefix = "KYC"

    def is_configured(self) -> bool:
        return False

    def get_status(
        self,
        *,
        subject: str,
        context: Mapping[str, Any] | None = None,
    ) -> ProviderResult:
        metadata: dict[str, Any] = {"subject": subject}
        if context:
            metadata["context_keys"] = sorted(context.keys())
        return self._not_configured_result(extra_metadata=metadata)
