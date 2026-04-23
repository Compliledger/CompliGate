"""Base abstractions for external compliance providers.

The provider layer normalizes results from heterogeneous external systems
(sanctions / watchlist screening, KYC / identity verification, reserve and
liquidity attestation) into a single :class:`ProviderResult` shape so the
rest of CompliGate (policy engine, permit issuance, audit log) can reason
about compliance signals without being coupled to any particular vendor.

Design goals:

* Vendor-neutral: nothing in this module imports from a specific provider
  SDK or speaks a vendor-specific protocol.
* Fail-closed by default: when no concrete provider is wired up the
  :class:`NotConfiguredProviderMixin` returns a deny decision so missing
  configuration cannot accidentally turn into an implicit "allow".
* Deterministic shape: every provider returns the same set of fields, which
  makes it safe to persist, hash, and reference from a permit / audit
  record.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

# Reason code emitted whenever a "not configured" provider fails closed.
PROVIDER_NOT_CONFIGURED_REASON = "PROVIDER_NOT_CONFIGURED"

# Environment flag that, when truthy, allows the "not configured" providers
# to return an explicit ALLOW decision for local development. Production
# deployments must leave this unset / false so the system fails closed.
_ALLOW_UNCONFIGURED_ENV = "ALLOW_UNCONFIGURED_PROVIDERS"
_TRUE_VALUES = ("true", "1", "yes", "on")


def _allow_unconfigured() -> bool:
    """Return True when unconfigured providers are explicitly allowed.

    This is read at call time (not import time) so tests and local dev can
    toggle the behavior without re-importing the module.
    """

    return os.getenv(_ALLOW_UNCONFIGURED_ENV, "").strip().lower() in _TRUE_VALUES


class ProviderStatus(str, Enum):
    """Operational status of a provider call.

    Distinct from :class:`ProviderDecision`: a call can succeed (``OK``) and
    still produce a ``DENY`` decision, or fail (``ERROR``) in which case the
    decision is conventionally ``DENY`` for fail-closed behavior.
    """

    OK = "ok"
    NOT_CONFIGURED = "not_configured"
    ERROR = "error"
    SKIPPED = "skipped"


class ProviderDecision(str, Enum):
    """Compliance decision derived from a provider response."""

    ALLOW = "allow"
    DENY = "deny"
    REVIEW = "review"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ProviderResult:
    """Normalized result returned by every compliance provider.

    Attributes:
        provider_name: Stable, human-readable identifier for the provider
            implementation (e.g. ``"sanctions:not_configured"``,
            ``"kyc:acme_idv"``).
        status: Operational status of the provider call.
        decision: Compliance decision the policy engine should consume.
        reason_codes: Machine-readable reason codes that justify the
            decision. Always upper-snake-case, ordered most- to
            least-significant.
        evidence_reference: Optional external reference (URL, document id,
            case id, etc.) that auditors can use to retrieve the original
            evidence from the provider. ``None`` when no external evidence
            exists.
        checked_at: UTC timestamp of when the check was performed.
        raw_response_excerpt: Small, non-sensitive excerpt of the raw
            provider response or normalized provider metadata, suitable for
            inclusion in audit logs. Implementations must not place
            secrets, full PII payloads, or unbounded blobs here.
    """

    provider_name: str
    status: ProviderStatus
    decision: ProviderDecision
    reason_codes: tuple[str, ...] = field(default_factory=tuple)
    evidence_reference: str | None = None
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_response_excerpt: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict (enums and datetimes stringified)."""

        data = asdict(self)
        data["status"] = self.status.value
        data["decision"] = self.decision.value
        data["reason_codes"] = list(self.reason_codes)
        data["checked_at"] = self.checked_at.astimezone(timezone.utc).isoformat()
        if self.raw_response_excerpt is not None:
            # Defensive copy so callers can mutate without poisoning the result.
            data["raw_response_excerpt"] = dict(self.raw_response_excerpt)
        return data


class ProviderError(Exception):
    """Base class for provider errors raised inside the abstraction layer."""


class ProviderNotConfiguredError(ProviderError):
    """Raised when a provider is invoked but no implementation is configured."""


class _BaseProvider(ABC):
    """Common functionality shared by every concrete provider.

    Subclasses set :attr:`provider_name` to a stable identifier and implement
    the domain-specific check method declared by the leaf interface
    (sanctions / KYC / reserve).
    """

    #: Stable identifier for the provider implementation. Concrete classes
    #: must override this with a non-empty string.
    provider_name: str = ""

    def _build_result(
        self,
        *,
        status: ProviderStatus,
        decision: ProviderDecision,
        reason_codes: tuple[str, ...] = (),
        evidence_reference: str | None = None,
        raw_response_excerpt: Mapping[str, Any] | None = None,
    ) -> ProviderResult:
        if not self.provider_name:
            raise ValueError("Concrete providers must define a non-empty provider_name")
        return ProviderResult(
            provider_name=self.provider_name,
            status=status,
            decision=decision,
            reason_codes=tuple(reason_codes),
            evidence_reference=evidence_reference,
            raw_response_excerpt=raw_response_excerpt,
        )


class NotConfiguredProviderMixin(_BaseProvider):
    """Shared "fail-closed" behavior for unconfigured providers.

    When :func:`_allow_unconfigured` returns False (the default), the mixin
    yields a ``DENY`` decision with status ``NOT_CONFIGURED``. When the
    ``ALLOW_UNCONFIGURED_PROVIDERS`` environment flag is set (intended for
    local development only), it instead returns an ``ALLOW`` decision with
    status ``SKIPPED`` so developers can exercise downstream code paths
    without standing up real providers.
    """

    #: Concrete subclasses set this to e.g. ``"SANCTIONS"`` so the reason
    #: codes are domain-specific.
    domain_reason_prefix: str = "PROVIDER"

    def _not_configured_result(
        self,
        *,
        extra_metadata: Mapping[str, Any] | None = None,
    ) -> ProviderResult:
        metadata: dict[str, Any] = {
            "configured": False,
            "allow_unconfigured": _allow_unconfigured(),
        }
        if extra_metadata:
            metadata.update(dict(extra_metadata))

        if _allow_unconfigured():
            return self._build_result(
                status=ProviderStatus.SKIPPED,
                decision=ProviderDecision.ALLOW,
                reason_codes=(
                    f"{self.domain_reason_prefix}_CHECK_SKIPPED_LOCAL_DEV",
                ),
                raw_response_excerpt=metadata,
            )

        return self._build_result(
            status=ProviderStatus.NOT_CONFIGURED,
            decision=ProviderDecision.DENY,
            reason_codes=(PROVIDER_NOT_CONFIGURED_REASON,),
            raw_response_excerpt=metadata,
        )


class _DomainProvider(_BaseProvider):
    """Marker base for the per-domain provider interfaces."""

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True when the provider has enough configuration to be called."""
