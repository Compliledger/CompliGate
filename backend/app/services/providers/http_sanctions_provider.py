"""Concrete HTTP-backed sanctions / address-screening provider.

This is the production implementation of the vendor-neutral
:class:`~app.services.providers.sanctions_provider.SanctionsProvider`
interface. It performs a real HTTPS address screening call against the
configured provider for the transaction subject and, when supplied, the
destination wallet, then normalizes the heterogeneous vendor responses
into a single :class:`ProviderResult`.

Design notes:

* **Vendor name + API key come from configuration** — the provider name
  is taken from ``SANCTIONS_PROVIDER`` and the API key from
  ``SANCTIONS_API_KEY`` (or the legacy ``SANCTIONS_PROVIDER_API_KEY``
  fallback).  Nothing is hard-coded.
* **Decision is always derived from the response** — the provider never
  hard-codes ``"pass"``.  The decision is derived from explicit fields
  in the response (``decision`` / ``status`` / ``hits``) or from the
  presence of any matches in the normalized hit list.
* **Fail-closed on any error** — transport failures, non-2xx responses,
  malformed JSON and missing configuration all return a result with
  ``status=ERROR``/``NOT_CONFIGURED`` and ``decision=UNAVAILABLE``.  The
  caller (compliance engine) is responsible for translating that into
  a permit denial when ``FAIL_CLOSED_COMPLIANCE`` is true.
* **Auditability without secrets** — the API key is sent in the
  ``Authorization`` header and is *never* placed in the evidence
  payload.  Subjects, jurisdiction and a small, bounded summary of the
  vendor's response (matched lists, score, top match name) are kept so
  auditors can reproduce the decision.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit, urlunsplit

import requests

from app.services.providers.base import (
    ProviderDecision,
    ProviderResult,
    ProviderStatus,
)
from app.services.providers.sanctions_provider import SanctionsProvider

logger = logging.getLogger("compligate.providers.sanctions")

#: Default per-screen HTTP timeout.  Sanctions screening calls must be
#: fast or we fail closed, so the timeout is intentionally tight.
DEFAULT_HTTP_TIMEOUT_SECONDS = 5.0

#: Maximum number of normalized hit records we keep in the evidence to
#: avoid unbounded payloads in the audit log.
MAX_EVIDENCE_HITS = 5

#: Type alias for an injectable HTTP fetcher used by tests.  The
#: implementation must return a dict with ``status_code``, ``json`` (a
#: callable returning parsed JSON) and ``url`` attributes — the same
#: surface area used from :mod:`requests`.
HttpFetcher = Callable[[str, dict[str, Any], dict[str, str], float], "_HttpResponse"]


class _HttpResponse:
    """Minimal protocol used by :class:`HttpSanctionsProvider`.

    Tests inject lightweight stand-ins; in production we delegate to
    :func:`requests.post` which already exposes this surface.
    """

    status_code: int
    url: str

    def json(self) -> Any:  # pragma: no cover - protocol declaration
        raise NotImplementedError


def _default_http_fetcher(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    timeout: float,
) -> _HttpResponse:
    return requests.post(url, json=payload, headers=headers, timeout=timeout)  # type: ignore[return-value]


class HttpSanctionsProvider(SanctionsProvider):
    """Real HTTP integration for sanctions / watchlist screening.

    The provider calls the configured screening endpoint once for the
    subject and, when the call context contains a non-empty
    ``destination`` (a.k.a. ``counterparty``), one additional time for
    the destination wallet.  Results are merged into a single
    :class:`ProviderResult`:

    * If **either** screen returns ``deny`` (a confirmed sanctions hit)
      the merged decision is ``deny``.
    * Else if **either** screen returns ``review`` (a possible match
      requiring manual review) the merged decision is ``review``.
    * Else if **either** screen returned an unavailable / errored
      response the merged decision is ``unavailable``.
    * Only when both screens explicitly returned ``pass`` is the merged
      decision ``pass``.  The decision is *never* defaulted to pass.
    """

    domain_reason_prefix = "SANCTIONS"

    def __init__(
        self,
        *,
        provider_name: str,
        url: str,
        api_key: str,
        timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
        fetcher: HttpFetcher | None = None,
    ) -> None:
        # ``provider_name`` is the configured vendor identifier (e.g.
        # ``"chainalysis"``); we namespace it so the audit log makes the
        # source unambiguous.
        cleaned_vendor = (provider_name or "").strip().lower() or "configured"
        self.provider_name = f"sanctions:{cleaned_vendor}"
        self._vendor = cleaned_vendor
        self._url = (url or "").strip()
        self._api_key = (api_key or "").strip()
        self._timeout = timeout
        self._fetcher: HttpFetcher = fetcher or _default_http_fetcher

    # ------------------------------------------------------------------
    # SanctionsProvider interface
    # ------------------------------------------------------------------

    def is_configured(self) -> bool:
        return bool(self._url) and bool(self._vendor)

    def screen(
        self,
        *,
        subject: str,
        context: Mapping[str, Any] | None = None,
    ) -> ProviderResult:
        if not self.is_configured():
            return self._unavailable_result(
                reason_code="SANCTIONS_PROVIDER_NOT_CONFIGURED",
                metadata={
                    "configured": False,
                    "has_url": bool(self._url),
                    "vendor": self._vendor,
                },
            )

        ctx: dict[str, Any] = dict(context or {})
        destination = _extract_destination(ctx)
        jurisdiction = ctx.get("jurisdiction")

        # Always screen the subject.
        subject_outcome = self._screen_one(
            address=subject,
            role="subject",
            jurisdiction=jurisdiction,
            extra_context=ctx,
        )

        outcomes: list[_ScreenOutcome] = [subject_outcome]
        # Also screen the destination wallet when the caller supplied
        # one and it differs from the subject (no point double-screening
        # the same address).
        if destination and destination != subject:
            outcomes.append(
                self._screen_one(
                    address=destination,
                    role="destination",
                    jurisdiction=jurisdiction,
                    extra_context=ctx,
                )
            )

        return self._merge_outcomes(outcomes)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _screen_one(
        self,
        *,
        address: str,
        role: str,
        jurisdiction: Any,
        extra_context: Mapping[str, Any],
    ) -> "_ScreenOutcome":
        payload: dict[str, Any] = {
            "address": address,
            "role": role,
            "vendor": self._vendor,
        }
        if jurisdiction:
            payload["jurisdiction"] = jurisdiction
        # Allow callers to pass an opaque ``asset`` mapping (currency /
        # issuer) so jurisdiction-aware vendors can refine the screen.
        asset = extra_context.get("asset")
        if isinstance(asset, Mapping):
            payload["asset"] = {
                k: asset.get(k)
                for k in ("currency", "issuer", "classification")
                if asset.get(k) is not None
            }

        headers: dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "CompliGate-SanctionsScreen/1.0",
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        try:
            response = self._fetcher(self._url, payload, headers, self._timeout)
        except Exception as exc:  # noqa: BLE001 - convert all errors
            logger.warning(
                "sanctions_screen_transport_error vendor=%s role=%s error=%s",
                self._vendor,
                role,
                exc.__class__.__name__,
            )
            return _ScreenOutcome.unavailable(
                role=role,
                address=address,
                reason_code="SANCTIONS_PROVIDER_TRANSPORT_ERROR",
                error_type=exc.__class__.__name__,
            )

        status_code = getattr(response, "status_code", 0) or 0
        if status_code < 200 or status_code >= 300:
            logger.warning(
                "sanctions_screen_http_error vendor=%s role=%s status=%s",
                self._vendor,
                role,
                status_code,
            )
            return _ScreenOutcome.unavailable(
                role=role,
                address=address,
                reason_code="SANCTIONS_PROVIDER_HTTP_ERROR",
                error_type=f"http_{status_code}",
            )

        try:
            body = response.json()
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "sanctions_screen_decode_error vendor=%s role=%s error=%s",
                self._vendor,
                role,
                exc.__class__.__name__,
            )
            return _ScreenOutcome.unavailable(
                role=role,
                address=address,
                reason_code="SANCTIONS_PROVIDER_INVALID_JSON",
                error_type=exc.__class__.__name__,
            )

        if not isinstance(body, Mapping):
            return _ScreenOutcome.unavailable(
                role=role,
                address=address,
                reason_code="SANCTIONS_PROVIDER_INVALID_PAYLOAD",
                error_type="non_object_response",
            )

        return _normalize_response(
            role=role,
            address=address,
            body=body,
            response_url=getattr(response, "url", self._url),
        )

    def _merge_outcomes(self, outcomes: list["_ScreenOutcome"]) -> ProviderResult:
        # Build the merged decision deterministically.  Order matters:
        # explicit deny beats review, which beats unavailable, which
        # beats pass.  We never default to pass.
        priority = {
            ProviderDecision.DENY: 4,
            ProviderDecision.REVIEW: 3,
            ProviderDecision.UNAVAILABLE: 2,
            ProviderDecision.PASS: 1,
        }
        merged_decision = max(
            (o.decision for o in outcomes),
            key=lambda d: priority.get(d, 0),
        )

        # The overall provider call status reflects whether *every* leg
        # of the screen completed cleanly.  If any leg was unavailable
        # we surface that at the top level as well so the engine can
        # apply fail-closed handling.
        any_unavailable = any(
            o.decision is ProviderDecision.UNAVAILABLE for o in outcomes
        )
        overall_status = (
            ProviderStatus.ERROR if any_unavailable else ProviderStatus.OK
        )

        reason_codes: list[str] = []
        for outcome in outcomes:
            for code in outcome.reason_codes:
                if code not in reason_codes:
                    reason_codes.append(code)
        if not reason_codes:
            # Make the merged "clean pass" outcome explicit so the
            # downstream audit log has at least one machine-readable
            # justification.
            reason_codes.append("SANCTIONS_NO_HITS")

        evidence_reference = next(
            (o.evidence_reference for o in outcomes if o.evidence_reference),
            None,
        )

        normalized_details: dict[str, Any] = {
            "vendor": self._vendor,
            "endpoint": _redact_endpoint(self._url),
            "screened": [o.to_evidence() for o in outcomes],
        }

        return ProviderResult(
            provider_name=self.provider_name,
            status=overall_status,
            decision=merged_decision,
            reason_codes=tuple(reason_codes),
            evidence_reference=evidence_reference,
            raw_response_excerpt=normalized_details,
        )

    def _unavailable_result(
        self,
        *,
        reason_code: str,
        metadata: Mapping[str, Any],
    ) -> ProviderResult:
        return ProviderResult(
            provider_name=self.provider_name,
            status=ProviderStatus.NOT_CONFIGURED,
            decision=ProviderDecision.UNAVAILABLE,
            reason_codes=(reason_code,),
            evidence_reference=None,
            raw_response_excerpt={
                "vendor": self._vendor,
                "endpoint": _redact_endpoint(self._url),
                **dict(metadata),
            },
        )


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


class _ScreenOutcome:
    """Per-leg outcome of a single address screen."""

    __slots__ = (
        "role",
        "address",
        "decision",
        "reason_codes",
        "evidence_reference",
        "details",
    )

    def __init__(
        self,
        *,
        role: str,
        address: str,
        decision: ProviderDecision,
        reason_codes: tuple[str, ...],
        evidence_reference: str | None,
        details: Mapping[str, Any],
    ) -> None:
        self.role = role
        self.address = address
        self.decision = decision
        self.reason_codes = reason_codes
        self.evidence_reference = evidence_reference
        self.details = dict(details)

    @classmethod
    def unavailable(
        cls,
        *,
        role: str,
        address: str,
        reason_code: str,
        error_type: str,
    ) -> "_ScreenOutcome":
        return cls(
            role=role,
            address=address,
            decision=ProviderDecision.UNAVAILABLE,
            reason_codes=(reason_code,),
            evidence_reference=None,
            details={"error_type": error_type},
        )

    def to_evidence(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "address": self.address,
            "decision": self.decision.value,
            "reason_codes": list(self.reason_codes),
            "evidence_reference": self.evidence_reference,
            "details": self.details,
        }


def _normalize_response(
    *,
    role: str,
    address: str,
    body: Mapping[str, Any],
    response_url: str,
) -> _ScreenOutcome:
    """Translate a heterogeneous vendor response into a normalized outcome.

    The function understands several common shapes:

    * ``{"decision": "pass" | "deny" | "review" | "unavailable", ...}``
    * ``{"status": "clear" | "match" | "potential_match" | "error", ...}``
    * ``{"hits": [...]}`` — any non-empty hit list is treated as a deny
      unless the hits explicitly mark themselves as ``"weak"`` /
      ``"potential"`` matches, in which case the decision is ``review``.

    Anything we can't classify falls back to ``unavailable`` so the
    engine can fail closed.
    """

    raw_decision = _coerce_str(body.get("decision"))
    raw_status = _coerce_str(body.get("status"))
    hits_raw = body.get("hits") or body.get("matches") or []
    if not isinstance(hits_raw, list):
        hits_raw = []
    normalized_hits = _normalize_hits(hits_raw)

    decision: ProviderDecision | None = None
    reason_codes: list[str] = []

    if raw_decision in {"pass", "clear", "no_match", "ok"}:
        decision = ProviderDecision.PASS
    elif raw_decision in {"deny", "denied", "block", "match", "hit"}:
        decision = ProviderDecision.DENY
    elif raw_decision in {"review", "potential", "potential_match", "manual_review"}:
        decision = ProviderDecision.REVIEW
    elif raw_decision in {"unavailable", "error", "unknown"}:
        decision = ProviderDecision.UNAVAILABLE
    elif raw_status in {"clear", "no_match", "ok", "pass"}:
        decision = ProviderDecision.PASS
    elif raw_status in {"match", "deny", "denied", "block", "hit"}:
        decision = ProviderDecision.DENY
    elif raw_status in {"potential_match", "review", "potential"}:
        decision = ProviderDecision.REVIEW
    elif raw_status in {"error", "unavailable"}:
        decision = ProviderDecision.UNAVAILABLE

    if decision is None:
        # Derive from the hit list if the vendor didn't give us an
        # explicit decision field.
        if normalized_hits:
            if all(hit.get("severity") in {"weak", "potential", "low"} for hit in normalized_hits):
                decision = ProviderDecision.REVIEW
            else:
                decision = ProviderDecision.DENY
        else:
            # No decision, no hits, no recognizable status — we cannot
            # safely infer "pass".  Fail-closed by reporting unavailable.
            return _ScreenOutcome.unavailable(
                role=role,
                address=address,
                reason_code="SANCTIONS_PROVIDER_INDETERMINATE",
                error_type="no_decision_and_no_hits",
            )

    if decision is ProviderDecision.DENY:
        lists = sorted({hit["list"] for hit in normalized_hits if hit.get("list")})
        if lists:
            for lst in lists:
                reason_codes.append(f"SANCTIONS_HIT_{_safe_token(lst)}")
        else:
            reason_codes.append("SANCTIONS_HIT")
    elif decision is ProviderDecision.REVIEW:
        reason_codes.append("SANCTIONS_POTENTIAL_MATCH")
    elif decision is ProviderDecision.UNAVAILABLE:
        reason_codes.append("SANCTIONS_PROVIDER_UNAVAILABLE")

    evidence_reference = (
        _coerce_str(body.get("evidence_reference"))
        or _coerce_str(body.get("reference"))
        or _coerce_str(body.get("case_id"))
        or _coerce_str(body.get("request_id"))
        or None
    )

    details: dict[str, Any] = {
        "endpoint": _redact_endpoint(response_url),
    }
    score = body.get("score")
    if isinstance(score, (int, float)):
        details["score"] = score
    if normalized_hits:
        details["hit_count"] = len(normalized_hits)
        details["hits"] = normalized_hits[:MAX_EVIDENCE_HITS]
    if raw_status:
        details["raw_status"] = raw_status
    if raw_decision:
        details["raw_decision"] = raw_decision

    return _ScreenOutcome(
        role=role,
        address=address,
        decision=decision,
        reason_codes=tuple(reason_codes),
        evidence_reference=evidence_reference,
        details=details,
    )


def _normalize_hits(hits: list[Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for raw in hits:
        if not isinstance(raw, Mapping):
            continue
        entry: dict[str, Any] = {}
        list_name = _coerce_str(raw.get("list") or raw.get("source") or raw.get("program"))
        if list_name:
            entry["list"] = list_name
        match_name = _coerce_str(raw.get("name") or raw.get("matched_name"))
        if match_name:
            entry["name"] = match_name
        severity = _coerce_str(raw.get("severity") or raw.get("match_strength"))
        if severity:
            entry["severity"] = severity
        score = raw.get("score")
        if isinstance(score, (int, float)):
            entry["score"] = score
        if entry:
            normalized.append(entry)
    return normalized


def _extract_destination(context: Mapping[str, Any]) -> str | None:
    for key in ("destination", "destination_address", "counterparty", "dest_wallet"):
        value = context.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _coerce_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower() if isinstance(value, str) else str(value).strip()


def _safe_token(value: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in value).strip("_").upper() or "UNKNOWN"


def _redact_endpoint(url: str) -> str:
    """Strip query / userinfo from the endpoint before logging it.

    We never want a stray ``?api_key=...`` query parameter (some
    legacy vendors accept that) to leak into the audit evidence.
    """
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    netloc = parts.hostname or ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def build_sanctions_provider_from_config(
    *,
    fetcher: HttpFetcher | None = None,
) -> "SanctionsProvider":
    """Construct the configured :class:`SanctionsProvider`.

    Reads ``SANCTIONS_PROVIDER`` (vendor name), ``SANCTIONS_PROVIDER_URL``
    and ``SANCTIONS_API_KEY`` from :mod:`app.core.config`.  When no real
    vendor is configured (the default), returns the fail-closed
    :class:`NotConfiguredSanctionsProvider` so callers always get a
    valid object back.
    """
    # Imported here to avoid a circular import at module-load time.
    from app.core import config
    from app.services.providers.sanctions_provider import (
        NotConfiguredSanctionsProvider,
    )

    vendor = (getattr(config, "SANCTIONS_PROVIDER", "") or "").strip()
    url = (getattr(config, "SANCTIONS_PROVIDER_URL", "") or "").strip()
    api_key = (getattr(config, "SANCTIONS_API_KEY", "") or "").strip()

    if not vendor or vendor.lower() in {"null", "none", "static_allow"} or not url:
        return NotConfiguredSanctionsProvider()

    return HttpSanctionsProvider(
        provider_name=vendor,
        url=url,
        api_key=api_key,
        fetcher=fetcher,
    )


__all__ = [
    "DEFAULT_HTTP_TIMEOUT_SECONDS",
    "HttpSanctionsProvider",
    "build_sanctions_provider_from_config",
]
