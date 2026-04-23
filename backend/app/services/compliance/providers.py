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
from app.services.compliance.kyc import (
    KycResult,
    KycStatus,
    validate_upstream_assertion,
)
from app.services.compliance.reserve import (
    ReserveResult,
    ReserveStatus,
    validate_reserve_attestation,
)

logger = get_logger("compliance")

#: Provider kinds that are explicitly *not* backed by a real third-party
#: check. They are still traceable in the proof artifact, but they must
#: never be treated as production-grade compliance evidence.
NON_PRODUCTION_PROVIDER_KINDS = frozenset({"null", "static_allow"})

#: Provider kinds supported for the KYC check. The KYC check uniquely
#: supports an ``upstream_assertion`` kind in addition to the
#: cross-cutting kinds, so a verified institutional system can submit a
#: signed assertion alongside the permit request instead of forcing
#: CompliGate to call a third-party identity-verification API.
_KYC_PROVIDER_KINDS = frozenset({"null", "static_allow", "http", "upstream_assertion"})
_RESERVE_PROVIDER_KINDS = frozenset({"null", "static_allow", "http", "attestation"})
_DEFAULT_PROVIDER_KINDS = frozenset({"null", "static_allow", "http", "address_screen"})

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
        details: dict[str, Any] = {}
        if self.check == "kyc":
            details["kyc_result"] = _kyc_result_from_status(
                provider_name=f"null:{self.check}",
                context=context,
                kyc_status=KycStatus.UNAVAILABLE,
                evidence_reference=None,
                reason_codes=("KYC_PROVIDER_NOT_CONFIGURED",),
            ).to_dict()
        elif self.check == "reserve":
            details["reserve_result"] = _reserve_result_from_status(
                provider_name=f"null:{self.check}",
                context=context,
                reserve_status=ReserveStatus.UNAVAILABLE,
                liquidity_status=ReserveStatus.UNAVAILABLE,
                evidence_reference=None,
                reason_codes=("RESERVE_PROVIDER_NOT_CONFIGURED",),
            ).to_dict()
        return ProviderResult(
            check=self.check,
            status=ProviderStatus.UNAVAILABLE,
            provider_id=f"null:{self.check}",
            reason="no_provider_configured",
            details=details,
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
        reference = f"static-{self.check}-{subject}"
        details: dict[str, Any] = {"mode": "dev"}
        if self.check == "kyc":
            details["kyc_result"] = _kyc_result_from_status(
                provider_name=f"static_allow:{self.check}",
                context=context,
                kyc_status=KycStatus.VERIFIED,
                evidence_reference=reference,
                reason_codes=("KYC_VERIFIED_VIA_STATIC_ALLOW_PROVIDER",),
            ).to_dict()
        elif self.check == "reserve":
            details["reserve_result"] = _reserve_result_from_status(
                provider_name=f"static_allow:{self.check}",
                context=context,
                reserve_status=ReserveStatus.VERIFIED,
                liquidity_status=ReserveStatus.VERIFIED,
                evidence_reference=reference,
                reason_codes=(
                    "RESERVE_EVIDENCE_VIA_STATIC_ALLOW_PROVIDER",
                ),
            ).to_dict()
        return ProviderResult(
            check=self.check,
            status=ProviderStatus.APPROVED,
            provider_id=f"static_allow:{self.check}",
            reference=reference,
            reason="static_allow_provider_configured",
            details=details,
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
                details=_with_kyc_evidence(
                    check=self.check,
                    provider_name=provider_id,
                    context=context,
                    status=ProviderStatus.UNAVAILABLE,
                    evidence_reference=None,
                    reason_codes=("KYC_PROVIDER_URL_MISSING",),
                ),
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
                details=_with_kyc_evidence(
                    check=self.check,
                    provider_name=provider_id,
                    context=context,
                    status=ProviderStatus.UNAVAILABLE,
                    evidence_reference=None,
                    reason_codes=("KYC_PROVIDER_REQUEST_FAILED",),
                    base_details={"error_type": exc.__class__.__name__},
                ),
            )

        raw_status = str(data.get("status", "")).lower()
        if self.check == "reserve":
            return _build_reserve_http_result(
                provider_id=provider_id,
                data=data,
                context=context,
                raw_status=raw_status,
            )
        try:
            status = ProviderStatus(raw_status)
        except ValueError:
            return ProviderResult(
                check=self.check,
                status=ProviderStatus.UNAVAILABLE,
                provider_id=provider_id,
                reason="provider_returned_unknown_status",
                details=_with_kyc_evidence(
                    check=self.check,
                    provider_name=provider_id,
                    context=context,
                    status=ProviderStatus.UNAVAILABLE,
                    evidence_reference=None,
                    reason_codes=("KYC_PROVIDER_RETURNED_UNKNOWN_STATUS",),
                    base_details={"raw_status": raw_status},
                ),
            )

        return ProviderResult(
            check=self.check,
            status=status,
            provider_id=provider_id,
            reference=data.get("reference"),
            reason=data.get("reason"),
            details=_with_kyc_evidence(
                check=self.check,
                provider_name=provider_id,
                context=context,
                status=status,
                evidence_reference=data.get("reference"),
                reason_codes=_reason_codes_from_response(data),
                base_details=(
                    data.get("details") if isinstance(data.get("details"), dict) else {}
                ),
            ),
        )


def _reason_codes_from_response(data: dict[str, Any]) -> tuple[str, ...]:
    raw = data.get("reason_codes")
    if isinstance(raw, (list, tuple)):
        return tuple(str(rc).strip() for rc in raw if str(rc).strip())
    if isinstance(raw, str) and raw.strip():
        return (raw.strip(),)
    reason = data.get("reason")
    if isinstance(reason, str) and reason.strip():
        return (reason.strip(),)
    return ()


def _kyc_result_from_status(
    *,
    provider_name: str,
    context: dict[str, Any],
    kyc_status: KycStatus,
    evidence_reference: str | None,
    reason_codes: tuple[str, ...],
) -> KycResult:
    """Build a normalized :class:`KycResult` from engine context.

    The jurisdiction is resolved from the request asset, the request
    context, and finally the global :mod:`app.core.config` default so
    the result always carries an explicit value.
    """
    asset = context.get("asset") if isinstance(context.get("asset"), dict) else {}
    jurisdiction = (
        context.get("jurisdiction")
        or (asset.get("jurisdiction") if asset else None)
        or getattr(config, "JURISDICTION", "")
        or ""
    )
    subject = str(context.get("subject") or "")
    return KycResult(
        provider_name=provider_name,
        subject_id=subject,
        kyc_status=kyc_status,
        jurisdiction=str(jurisdiction),
        evidence_reference=evidence_reference,
        reason_codes=reason_codes,
    )


def _kyc_status_from_provider_status(status: ProviderStatus) -> KycStatus:
    if status is ProviderStatus.APPROVED:
        return KycStatus.VERIFIED
    if status is ProviderStatus.DENIED:
        return KycStatus.NOT_VERIFIED
    return KycStatus.UNAVAILABLE


def _resolve_asset_currency(context: dict[str, Any]) -> str:
    """Resolve the asset currency the reserve check relates to.

    Tries the request asset, the request context, and finally the
    global :mod:`app.core.config` default so callers always have a
    non-empty value to bind a reserve attestation against.
    """
    asset = context.get("asset") if isinstance(context.get("asset"), dict) else {}
    asset_currency = (
        (asset.get("currency") if asset else None)
        or context.get("currency")
        or getattr(config, "CURRENCY", "")
        or ""
    )
    return str(asset_currency)


def _reserve_result_from_status(
    *,
    provider_name: str,
    context: dict[str, Any],  # noqa: ARG001 - kept for symmetry / future use
    reserve_status: ReserveStatus,
    liquidity_status: ReserveStatus,
    evidence_reference: str | None,
    reason_codes: tuple[str, ...],
) -> ReserveResult:
    """Build a normalized :class:`ReserveResult` from engine context."""
    return ReserveResult(
        provider_name=provider_name,
        reserve_status=reserve_status,
        liquidity_status=liquidity_status,
        evidence_reference=evidence_reference,
        reason_codes=reason_codes,
    )


def _provider_status_from_reserve_pair(
    reserve_status: ReserveStatus,
    liquidity_status: ReserveStatus,
) -> ProviderStatus:
    """Collapse the ``(reserve, liquidity)`` pair into the engine-level status.

    * APPROVED  — both dimensions explicitly verified.
    * DENIED    — either dimension explicitly not_verified.
    * UNAVAILABLE — anything else (at least one dimension lacks
      conclusive evidence).
    """
    if (
        reserve_status is ReserveStatus.NOT_VERIFIED
        or liquidity_status is ReserveStatus.NOT_VERIFIED
    ):
        return ProviderStatus.DENIED
    if (
        reserve_status is ReserveStatus.VERIFIED
        and liquidity_status is ReserveStatus.VERIFIED
    ):
        return ProviderStatus.APPROVED
    return ProviderStatus.UNAVAILABLE


def _build_reserve_http_result(
    *,
    provider_id: str,
    data: dict[str, Any],
    context: dict[str, Any],
    raw_status: str,
) -> ProviderResult:
    """Translate an HTTP reserve provider response into a ProviderResult.

    The reserve provider response is expected to carry an explicit
    ``reserve_status`` and ``liquidity_status`` (``verified`` /
    ``not_verified`` / ``unavailable``). For backward compatibility a
    response with only the legacy top-level ``status`` field is also
    accepted: ``approved`` is treated as both reserve and liquidity
    verified, ``denied`` as both not_verified, and ``unavailable`` as
    both unavailable.
    """
    from app.services.compliance.reserve import _coerce_status as _reserve_coerce

    reason_codes_from_response = list(_reason_codes_from_response(data))
    base_details = (
        dict(data.get("details")) if isinstance(data.get("details"), dict) else {}
    )

    reserve_status_raw = data.get("reserve_status")
    liquidity_status_raw = data.get("liquidity_status")
    has_explicit_pair = (
        reserve_status_raw is not None or liquidity_status_raw is not None
    )

    if has_explicit_pair:
        reserve_status = _reserve_coerce(reserve_status_raw)
        liquidity_status = _reserve_coerce(liquidity_status_raw)
        if reserve_status is None or liquidity_status is None:
            return ProviderResult(
                check="reserve",
                status=ProviderStatus.UNAVAILABLE,
                provider_id=provider_id,
                reason="provider_returned_unknown_reserve_or_liquidity_status",
                details={
                    **base_details,
                    "raw_reserve_status": str(reserve_status_raw or ""),
                    "raw_liquidity_status": str(liquidity_status_raw or ""),
                    "reserve_result": _reserve_result_from_status(
                        provider_name=provider_id,
                        context=context,
                        reserve_status=ReserveStatus.UNAVAILABLE,
                        liquidity_status=ReserveStatus.UNAVAILABLE,
                        evidence_reference=data.get("reference"),
                        reason_codes=(
                            "RESERVE_PROVIDER_RETURNED_UNKNOWN_STATUS",
                        ),
                    ).to_dict(),
                },
            )
    else:
        try:
            legacy_status = ProviderStatus(raw_status)
        except ValueError:
            return ProviderResult(
                check="reserve",
                status=ProviderStatus.UNAVAILABLE,
                provider_id=provider_id,
                reason="provider_returned_unknown_status",
                details={
                    **base_details,
                    "raw_status": raw_status,
                    "reserve_result": _reserve_result_from_status(
                        provider_name=provider_id,
                        context=context,
                        reserve_status=ReserveStatus.UNAVAILABLE,
                        liquidity_status=ReserveStatus.UNAVAILABLE,
                        evidence_reference=data.get("reference"),
                        reason_codes=(
                            "RESERVE_PROVIDER_RETURNED_UNKNOWN_STATUS",
                        ),
                    ).to_dict(),
                },
            )
        if legacy_status is ProviderStatus.APPROVED:
            reserve_status = ReserveStatus.VERIFIED
            liquidity_status = ReserveStatus.VERIFIED
        elif legacy_status is ProviderStatus.DENIED:
            reserve_status = ReserveStatus.NOT_VERIFIED
            liquidity_status = ReserveStatus.NOT_VERIFIED
        else:
            reserve_status = ReserveStatus.UNAVAILABLE
            liquidity_status = ReserveStatus.UNAVAILABLE

    overall_status = _provider_status_from_reserve_pair(
        reserve_status, liquidity_status
    )
    reserve_result = _reserve_result_from_status(
        provider_name=provider_id,
        context=context,
        reserve_status=reserve_status,
        liquidity_status=liquidity_status,
        evidence_reference=data.get("reference"),
        reason_codes=tuple(reason_codes_from_response),
    )
    base_details["reserve_result"] = reserve_result.to_dict()
    return ProviderResult(
        check="reserve",
        status=overall_status,
        provider_id=provider_id,
        reference=data.get("reference"),
        reason=data.get("reason"),
        details=base_details,
    )


def _with_kyc_evidence(
    *,
    check: str,
    provider_name: str,
    context: dict[str, Any],
    status: ProviderStatus,
    evidence_reference: str | None,
    reason_codes: tuple[str, ...],
    base_details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return ``base_details`` with a normalized ``kyc_result`` attached.

    A no-op for non-KYC checks so the helper can be used uniformly.
    """
    details = dict(base_details or {})
    if check != "kyc":
        return details
    kyc_status = _kyc_status_from_provider_status(status)
    details["kyc_result"] = _kyc_result_from_status(
        provider_name=provider_name,
        context=context,
        kyc_status=kyc_status,
        evidence_reference=evidence_reference,
        reason_codes=reason_codes,
    ).to_dict()
    return details


class _UpstreamAssertionKycProvider(ComplianceProvider):
    """KYC provider backed by a trusted upstream institutional assertion.

    Instead of CompliGate calling a third-party identity-verification
    API, an upstream institutional system (custodian, broker-dealer,
    regulated exchange, …) submits a signed assertion alongside the
    permit request. The assertion is validated against a configured
    HMAC shared secret and an allowlist of trusted issuer identifiers
    (see :mod:`app.services.compliance.kyc`).

    The provider returns:

    * ``APPROVED`` when the assertion is valid **and** its
      ``kyc_status`` is ``verified``;
    * ``DENIED`` when the assertion is valid but the upstream system
      explicitly reports ``not_verified``;
    * ``UNAVAILABLE`` for every other case (assertion missing,
      malformed, expired, signed by an untrusted issuer, signature
      mismatch, subject mismatch, …) so the engine can fail closed
      under ``FAIL_CLOSED_COMPLIANCE``.

    In every case the engine evidence carries the full normalized
    :class:`KycResult` so the proof artifact records exactly which
    institutional source the decision was based on (or why no usable
    upstream evidence was available).
    """

    check = "kyc"
    kind = "upstream_assertion"

    def __init__(
        self,
        *,
        secret: str | None = None,
        trusted_issuers: tuple[str, ...] | list[str] | None = None,
    ) -> None:
        self._secret = (
            secret
            if secret is not None
            else (getattr(config, "KYC_UPSTREAM_ASSERTION_SECRET", "") or "")
        )
        if trusted_issuers is None:
            trusted_issuers = getattr(
                config, "KYC_UPSTREAM_ASSERTION_TRUSTED_ISSUERS", ()
            )
        self._trusted_issuers = tuple(trusted_issuers or ())

    def evaluate(self, context: dict[str, Any]) -> ProviderResult:
        subject = str(context.get("subject") or "")
        assertion = context.get("kyc_assertion")
        if assertion is not None and not isinstance(assertion, dict):
            assertion = None

        outcome = validate_upstream_assertion(
            assertion=assertion,
            subject=subject,
            trusted_issuers=self._trusted_issuers,
            secret=self._secret,
        )
        kyc_result = outcome.result
        provider_id = kyc_result.provider_name

        if not outcome.valid:
            return ProviderResult(
                check=self.check,
                status=ProviderStatus.UNAVAILABLE,
                provider_id=provider_id,
                reference=kyc_result.evidence_reference,
                reason=outcome.error,
                details={"kyc_result": kyc_result.to_dict()},
            )

        if kyc_result.kyc_status is KycStatus.VERIFIED:
            status = ProviderStatus.APPROVED
            reason = "KYC_VERIFIED_VIA_UPSTREAM_ASSERTION"
        elif kyc_result.kyc_status is KycStatus.NOT_VERIFIED:
            status = ProviderStatus.DENIED
            reason = "KYC_NOT_VERIFIED_VIA_UPSTREAM_ASSERTION"
        else:
            status = ProviderStatus.UNAVAILABLE
            reason = "KYC_UPSTREAM_ASSERTION_STATUS_UNAVAILABLE"

        return ProviderResult(
            check=self.check,
            status=status,
            provider_id=provider_id,
            reference=kyc_result.evidence_reference,
            reason=reason,
            details={"kyc_result": kyc_result.to_dict()},
        )


class _AttestationReserveProvider(ComplianceProvider):
    """Reserve provider backed by a trusted custodian / auditor / issuer
    attestation.

    Instead of CompliGate calling a live reserve / proof-of-reserves
    API, an upstream evidence source (custodian, independent auditor,
    or the asset issuer itself) submits a signed attestation alongside
    the permit request. The attestation is validated against a
    configured HMAC shared secret and an allowlist of trusted attestor
    identifiers (see :mod:`app.services.compliance.reserve`).

    The provider returns:

    * ``APPROVED`` when the attestation is valid **and** both
      ``reserve_status`` and ``liquidity_status`` are ``verified``;
    * ``DENIED`` when the attestation is valid but either dimension is
      explicitly ``not_verified``;
    * ``UNAVAILABLE`` for every other case (attestation missing,
      malformed, expired, signed by an untrusted attestor, signature
      mismatch, asset mismatch, …) so the engine can fail closed under
      ``FAIL_CLOSED_COMPLIANCE``.

    In every case the engine evidence carries the full normalized
    :class:`ReserveResult` so the proof artifact records exactly which
    attestation source the decision was based on (or why no usable
    attestation evidence was available).
    """

    check = "reserve"
    kind = "attestation"

    def __init__(
        self,
        *,
        secret: str | None = None,
        trusted_attestors: tuple[str, ...] | list[str] | None = None,
    ) -> None:
        self._secret = (
            secret
            if secret is not None
            else (getattr(config, "RESERVE_ATTESTATION_SECRET", "") or "")
        )
        if trusted_attestors is None:
            trusted_attestors = getattr(
                config, "RESERVE_ATTESTATION_TRUSTED_ATTESTORS", ()
            )
        self._trusted_attestors = tuple(trusted_attestors or ())

    def evaluate(self, context: dict[str, Any]) -> ProviderResult:
        asset_currency = _resolve_asset_currency(context)
        attestation = context.get("reserve_attestation")
        if attestation is not None and not isinstance(attestation, dict):
            attestation = None

        outcome = validate_reserve_attestation(
            attestation=attestation,
            asset=asset_currency,
            trusted_attestors=self._trusted_attestors,
            secret=self._secret,
        )
        reserve_result = outcome.result
        provider_id = reserve_result.provider_name

        if not outcome.valid:
            return ProviderResult(
                check=self.check,
                status=ProviderStatus.UNAVAILABLE,
                provider_id=provider_id,
                reference=reserve_result.evidence_reference,
                reason=outcome.error,
                details={"reserve_result": reserve_result.to_dict()},
            )

        status = _provider_status_from_reserve_pair(
            reserve_result.reserve_status,
            reserve_result.liquidity_status,
        )
        if status is ProviderStatus.APPROVED:
            reason = "RESERVE_VERIFIED_VIA_ATTESTATION"
        elif status is ProviderStatus.DENIED:
            reason = "RESERVE_NOT_VERIFIED_VIA_ATTESTATION"
        else:
            reason = "RESERVE_ATTESTATION_STATUS_UNAVAILABLE"

        return ProviderResult(
            check=self.check,
            status=status,
            provider_id=provider_id,
            reference=reserve_result.evidence_reference,
            reason=reason,
            details={"reserve_result": reserve_result.to_dict()},
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


def _read_provider_kind(env_name: str, *, allowed_kinds: frozenset[str] | None = None) -> str:
    allowed = allowed_kinds or _DEFAULT_PROVIDER_KINDS
    raw = getattr(config, env_name, "") or ""
    kind = raw.strip().lower() or "null"
    if kind not in allowed:
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
    allowed_kinds: frozenset[str] | None = None,
) -> ComplianceProvider:
    kind = _read_provider_kind(kind_env, allowed_kinds=allowed_kinds)
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
    if kind == "upstream_assertion":
        if check != "kyc":
            logger.warning(
                "upstream_assertion_kind_only_supported_for_kyc check=%s -> null",
                check,
            )
            return _NullProvider(check)
        return _UpstreamAssertionKycProvider()
    if kind == "attestation":
        if check != "reserve":
            logger.warning(
                "attestation_kind_only_supported_for_reserve check=%s -> null",
                check,
            )
            return _NullProvider(check)
        return _AttestationReserveProvider()
    return _NullProvider(check)


def get_kyc_provider() -> ComplianceProvider:
    return _build_provider(
        check="kyc",
        kind_env="KYC_PROVIDER",
        url_env="KYC_PROVIDER_URL",
        api_key_env="KYC_PROVIDER_API_KEY",
        provider_name="kyc",
        allowed_kinds=_KYC_PROVIDER_KINDS,
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
        allowed_kinds=_RESERVE_PROVIDER_KINDS,
    )
