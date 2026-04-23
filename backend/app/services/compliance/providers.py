"""Compliance provider abstractions and built-in implementations.

A provider answers a single compliance question (KYC, sanctions screening,
or 1:1 reserve attestation) and returns a :class:`ProviderResult`. The
result is what gets persisted as evidence in the proof artifact, so it
must be reproducible and traceable to the provider that produced it.

Three built-in provider kinds are supported:

``null``
    No provider is configured. Returns ``unavailable``. Combined with the
    fail-closed engine policy this denies the request with an explicit
    ``*_PROVIDER_UNAVAILABLE`` reason code. This is the default so that
    CompliGate never silently approves anything.

``static_allow``
    Explicit, traceable approval used for local development and tests.
    The provider id (e.g. ``static_allow:dev``) is recorded in the
    evidence so it is obvious in the proof artifact that no real
    third-party check was performed. This is **not** suitable for
    production and is rejected by :func:`require_production_provider`.

``http``
    Calls a configured HTTPS endpoint (provider URL + API key) and uses
    the JSON response as the evidence. On any transport, status, or
    parsing error it returns ``unavailable`` so the engine fails closed.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

import requests

from app.core import config
from app.core.logging import get_logger

logger = get_logger("compliance")

#: Provider kinds that are explicitly *not* backed by a real third-party
#: check. They are still traceable in the proof artifact, but they must
#: never be treated as production-grade compliance evidence.
NON_PRODUCTION_PROVIDER_KINDS = frozenset({"null", "static_allow"})

_HTTP_TIMEOUT_SECONDS = 5.0


class ProviderStatus(str, Enum):
    """Outcome of a single provider check."""

    APPROVED = "approved"
    DENIED = "denied"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class ProviderResult:
    """Structured, persistable result returned by a compliance provider."""

    check: str
    status: ProviderStatus
    provider_id: str
    reference: str | None = None
    reason: str | None = None
    checked_at: int = field(default_factory=lambda: int(time.time()))
    details: dict[str, Any] = field(default_factory=dict)

    def to_evidence(self) -> dict[str, Any]:
        """Return a JSON-serializable evidence record for proof artifacts."""
        return {
            "check": self.check,
            "status": self.status.value,
            "provider_id": self.provider_id,
            "reference": self.reference,
            "reason": self.reason,
            "checked_at": self.checked_at,
            "details": self.details,
        }


class ComplianceProvider(ABC):
    """Abstract provider returning a :class:`ProviderResult` for one check."""

    #: Logical name of the check this provider answers (``kyc``,
    #: ``sanctions``, ``reserve``).
    check: str

    #: Provider kind identifier (``null``, ``static_allow``, ``http`` …).
    kind: str

    @abstractmethod
    def evaluate(self, context: dict[str, Any]) -> ProviderResult:
        """Run the check and return its result.

        Implementations must never raise: transport / parsing errors must
        be converted into an ``unavailable`` :class:`ProviderResult` so
        the engine can fail closed deterministically.
        """


class _NullProvider(ComplianceProvider):
    """Default provider used when nothing is configured.

    Always returns ``unavailable`` so the engine fails closed and the
    proof artifact records exactly why the decision was a denial.
    """

    kind = "null"

    def __init__(self, check: str) -> None:
        self.check = check

    def evaluate(self, context: dict[str, Any]) -> ProviderResult:  # noqa: ARG002
        return ProviderResult(
            check=self.check,
            status=ProviderStatus.UNAVAILABLE,
            provider_id=f"null:{self.check}",
            reason="no_provider_configured",
        )


class _StaticAllowProvider(ComplianceProvider):
    """Explicitly-traceable approval provider for development and tests.

    The provider id makes it unambiguous in the proof artifact that no
    real third-party check was performed.
    """

    kind = "static_allow"

    def __init__(self, check: str) -> None:
        self.check = check

    def evaluate(self, context: dict[str, Any]) -> ProviderResult:
        subject = context.get("subject") or context.get("entity") or "unknown"
        return ProviderResult(
            check=self.check,
            status=ProviderStatus.APPROVED,
            provider_id=f"static_allow:{self.check}",
            reference=f"static-{self.check}-{subject}",
            reason="static_allow_provider_configured",
            details={"mode": "dev"},
        )


HttpFetcher = Callable[[str, dict[str, Any], dict[str, str]], dict[str, Any]]


def _default_http_fetcher(url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    response = requests.post(url, json=payload, headers=headers, timeout=_HTTP_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json()


class _HttpProvider(ComplianceProvider):
    """Provider that delegates the check to a real HTTP endpoint.

    The remote service is expected to return a JSON object with at least
    a ``status`` field (``approved`` / ``denied`` / ``unavailable``) and
    optionally ``reference``, ``reason`` and ``details``. Any error,
    timeout or unexpected payload is converted into ``unavailable`` so
    the engine fails closed.
    """

    kind = "http"

    def __init__(
        self,
        check: str,
        url: str,
        api_key: str,
        *,
        provider_name: str,
        fetcher: HttpFetcher | None = None,
    ) -> None:
        self.check = check
        self._url = url
        self._api_key = api_key
        self._provider_name = provider_name
        self._fetcher = fetcher or _default_http_fetcher

    def evaluate(self, context: dict[str, Any]) -> ProviderResult:
        provider_id = f"http:{self._provider_name or self.check}"
        if not self._url:
            return ProviderResult(
                check=self.check,
                status=ProviderStatus.UNAVAILABLE,
                provider_id=provider_id,
                reason="provider_url_missing",
            )
        payload = {"check": self.check, **context}
        headers: dict[str, str] = {"Accept": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        try:
            data = self._fetcher(self._url, payload, headers)
        except Exception as exc:  # noqa: BLE001 - convert all errors to unavailable
            logger.warning(
                "compliance_provider_unavailable check=%s provider=%s error=%s",
                self.check,
                provider_id,
                exc.__class__.__name__,
            )
            return ProviderResult(
                check=self.check,
                status=ProviderStatus.UNAVAILABLE,
                provider_id=provider_id,
                reason="provider_request_failed",
                details={"error_type": exc.__class__.__name__},
            )

        raw_status = str(data.get("status", "")).lower()
        try:
            status = ProviderStatus(raw_status)
        except ValueError:
            return ProviderResult(
                check=self.check,
                status=ProviderStatus.UNAVAILABLE,
                provider_id=provider_id,
                reason="provider_returned_unknown_status",
                details={"raw_status": raw_status},
            )

        return ProviderResult(
            check=self.check,
            status=status,
            provider_id=provider_id,
            reference=data.get("reference"),
            reason=data.get("reason"),
            details=data.get("details", {}) if isinstance(data.get("details"), dict) else {},
        )


class _AddressScreenSanctionsProvider(ComplianceProvider):
    """Adapter that drives the real :class:`HttpSanctionsProvider`.

    The vendor-neutral abstraction layer in :mod:`app.services.providers`
    returns a richer :class:`~app.services.providers.ProviderResult`
    (with a ``decision`` of ``pass`` / ``deny`` / ``review`` /
    ``unavailable``).  This adapter translates that into the
    engine-level :class:`ProviderResult` shape so the existing
    compliance engine — which already implements the fail-closed
    policy required by ``FAIL_CLOSED_COMPLIANCE`` — can consume it
    without modification.
    """

    check = "sanctions"
    kind = "address_screen"

    def __init__(
        self,
        *,
        provider_factory: Callable[[], Any] | None = None,
    ) -> None:
        # Late-imported to avoid a circular import at module load.
        from app.services.providers import (  # noqa: WPS433 - intentional
            build_sanctions_provider_from_config,
        )

        self._provider_factory = (
            provider_factory or build_sanctions_provider_from_config
        )

    def evaluate(self, context: dict[str, Any]) -> ProviderResult:
        from app.services.providers import (  # noqa: WPS433 - intentional
            ProviderDecision as AbstractDecision,
        )

        provider = self._provider_factory()
        subject = str(context.get("subject") or "")
        screen_context: dict[str, Any] = {
            k: v
            for k, v in context.items()
            if k in {"counterparty", "destination", "destination_address",
                     "asset", "jurisdiction", "action", "amount"}
            and v is not None
        }
        # The abstraction layer prefers an explicit "destination" key.
        if "destination" not in screen_context and context.get("counterparty"):
            screen_context["destination"] = context.get("counterparty")

        try:
            normalized = provider.screen(subject=subject, context=screen_context)
        except Exception as exc:  # noqa: BLE001 - never raise to engine
            logger.warning(
                "sanctions_address_screen_unexpected_error error=%s",
                exc.__class__.__name__,
            )
            return ProviderResult(
                check=self.check,
                status=ProviderStatus.UNAVAILABLE,
                provider_id="address_screen:unavailable",
                reason="provider_request_failed",
                details={"error_type": exc.__class__.__name__},
            )

        provider_id = f"address_screen:{normalized.provider_name}"

        # Map the normalized decision onto the engine status.
        #
        # * ``pass``         -> APPROVED   (permit may be issued)
        # * ``deny``         -> DENIED     (confirmed sanctions hit)
        # * ``review``       -> DENIED     (deny / conditional deny for
        #                                   MVP — a manual review hold
        #                                   must never auto-issue a
        #                                   permit; we make the cause
        #                                   explicit via the reason
        #                                   field rather than collapsing
        #                                   into "unavailable")
        # * ``unavailable``  -> UNAVAILABLE (fail-closed via engine when
        #                                    FAIL_CLOSED_COMPLIANCE=true)
        review_denied = False
        if normalized.decision is AbstractDecision.PASS:
            status = ProviderStatus.APPROVED
        elif normalized.decision is AbstractDecision.DENY:
            status = ProviderStatus.DENIED
        elif normalized.decision is AbstractDecision.REVIEW:
            status = ProviderStatus.DENIED
            review_denied = True
        else:
            status = ProviderStatus.UNAVAILABLE

        # Build a JSON-friendly, secret-free details payload from the
        # provider's normalized response excerpt.  The raw decision is
        # always preserved so auditors can see whether a denial was the
        # result of a confirmed hit or a review-hold escalation.
        details: dict[str, Any] = {
            "decision": normalized.decision.value,
            "reason_codes": list(normalized.reason_codes),
        }
        if review_denied:
            details["review_denied_for_mvp"] = True
        if normalized.raw_response_excerpt is not None:
            details["normalized"] = dict(normalized.raw_response_excerpt)

        if review_denied:
            reason = "SANCTIONS_REVIEW_DENIED_FOR_MVP"
        else:
            reason = normalized.reason_codes[0] if normalized.reason_codes else None

        return ProviderResult(
            check=self.check,
            status=status,
            provider_id=provider_id,
            reference=normalized.evidence_reference,
            reason=reason,
            details=details,
        )


def _read_provider_kind(env_name: str) -> str:
    raw = getattr(config, env_name, "") or ""
    kind = raw.strip().lower() or "null"
    if kind not in {"null", "static_allow", "http", "address_screen"}:
        logger.warning("unknown_compliance_provider_kind env=%s value=%s -> null", env_name, kind)
        return "null"
    return kind


def _build_provider(
    *,
    check: str,
    kind_env: str,
    url_env: str,
    api_key_env: str,
    provider_name: str,
) -> ComplianceProvider:
    kind = _read_provider_kind(kind_env)
    if kind == "static_allow":
        return _StaticAllowProvider(check)
    if kind == "http":
        url = (getattr(config, url_env, "") or "").strip()
        api_key = (getattr(config, api_key_env, "") or "").strip()
        return _HttpProvider(check, url, api_key, provider_name=provider_name)
    if kind == "address_screen":
        if check != "sanctions":
            logger.warning(
                "address_screen_kind_only_supported_for_sanctions check=%s -> null",
                check,
            )
            return _NullProvider(check)
        return _AddressScreenSanctionsProvider()
    return _NullProvider(check)


def get_kyc_provider() -> ComplianceProvider:
    return _build_provider(
        check="kyc",
        kind_env="KYC_PROVIDER",
        url_env="KYC_PROVIDER_URL",
        api_key_env="KYC_PROVIDER_API_KEY",
        provider_name="kyc",
    )


def get_sanctions_provider() -> ComplianceProvider:
    return _build_provider(
        check="sanctions",
        kind_env="SANCTIONS_PROVIDER",
        url_env="SANCTIONS_PROVIDER_URL",
        api_key_env="SANCTIONS_PROVIDER_API_KEY",
        provider_name="sanctions",
    )


def get_reserve_provider() -> ComplianceProvider:
    return _build_provider(
        check="reserve",
        kind_env="RESERVE_PROVIDER",
        url_env="RESERVE_PROVIDER_URL",
        api_key_env="RESERVE_PROVIDER_API_KEY",
        provider_name="reserve",
    )
