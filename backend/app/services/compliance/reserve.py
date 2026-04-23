"""Normalized reserve / liquidity evidence and attestation validation.

CompliGate is an authorization layer; it does not invent reserve or
liquidity state. Reserve evidence reaches the compliance engine through
one of two supported paths:

1. **Live reserve provider integration** — a real reserve / proof-of-
   reserves service is called over HTTPS (see the ``http`` reserve
   provider kind in :mod:`app.services.compliance.providers`).
2. **Attestation ingestion from a custodian / auditor / issuer evidence
   source** — a trusted attestor (custodian, independent auditor, or the
   issuer itself) submits a signed attestation alongside the permit
   request. The attestation is verified against a configured HMAC shared
   secret and an allowlist of trusted attestor identifiers.

In both cases the engine surfaces a single normalized
:class:`ReserveResult` so downstream consumers (permit bundle, proof
artifact, audit logs) never have to reason about source-specific shapes
— and reserve / liquidity outcomes are *always* derived from real
evidence.

When neither path is configured (or the attestation is missing /
invalid) the engine falls back to its fail-closed policy and denies the
request with a ``RESERVE_PROVIDER_UNAVAILABLE`` reason code as long as
``FAIL_CLOSED_COMPLIANCE=true`` (the default).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class ReserveStatus(str, Enum):
    """Normalized reserve / liquidity outcome.

    The vocabulary is intentionally narrow: the asset's reserves /
    liquidity are either **verified** by a trusted source, explicitly
    **not_verified**, or no usable evidence is available.
    """

    VERIFIED = "verified"
    NOT_VERIFIED = "not_verified"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class ReserveResult:
    """Normalized, persistable reserve / liquidity evidence.

    The shape is identical regardless of whether the result came from a
    direct reserve provider integration or a trusted custodian /
    auditor / issuer attestation, so the bundle / proof artifact never
    has to special-case the source.

    Attributes:
        provider_name: Stable identifier of the reserve evidence source.
            Either the configured reserve provider name (``"http:reserve"``,
            ``"static_allow:reserve"``, …) or the attestor identifier
            (``"attestation:<attestor>"``) when the result came from a
            trusted attestation. Aliased as ``attestor_name`` via
            :attr:`attestor_name` for callers who prefer that name.
        reserve_status: Normalized 1:1 reserve-backing outcome —
            ``verified`` / ``not_verified`` / ``unavailable``.
        liquidity_status: Normalized liquidity outcome — same vocabulary
            as ``reserve_status``. Reserve and liquidity are reported
            independently so callers can tell which dimension failed.
        evidence_reference: Optional external reference (attestation id,
            document hash, case id) auditors can use to retrieve the
            original evidence.
        checked_at: UNIX timestamp (seconds) of when the underlying
            check was performed by the source system.
        reason_codes: Machine-readable reason codes that justify the
            outcome. Always upper-snake-case, ordered most- to
            least-significant.
    """

    provider_name: str
    reserve_status: ReserveStatus
    liquidity_status: ReserveStatus
    evidence_reference: str | None = None
    checked_at: int = field(default_factory=lambda: int(time.time()))
    reason_codes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def attestor_name(self) -> str:
        """Alias of :attr:`provider_name`.

        The requirement language uses ``provider_name`` for live
        provider integrations and ``attestor_name`` for attestation
        ingestion; we keep a single underlying field and expose both
        names so callers can use whichever fits their domain language.
        """
        return self.provider_name

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""
        return {
            "provider_name": self.provider_name,
            "attestor_name": self.provider_name,
            "reserve_status": self.reserve_status.value,
            "liquidity_status": self.liquidity_status.value,
            "evidence_reference": self.evidence_reference,
            "checked_at": self.checked_at,
            "reason_codes": list(self.reason_codes),
        }


# ---------------------------------------------------------------------------
# Trusted reserve attestation validation
# ---------------------------------------------------------------------------

#: Maximum age of a valid reserve attestation in seconds. Attestations
#: older than this are rejected so a leaked signed payload cannot be
#: replayed indefinitely.
DEFAULT_ATTESTATION_MAX_AGE_SECONDS = 24 * 60 * 60  # 24h

#: Tolerated clock skew between the upstream attestor and CompliGate
#: when validating ``checked_at``. Anything beyond this margin in the
#: future is treated as a forged / misconfigured attestation.
ATTESTATION_CLOCK_SKEW_MARGIN_SECONDS = 60


@dataclass(frozen=True)
class AttestationValidationOutcome:
    """Outcome of validating a trusted reserve / liquidity attestation."""

    result: ReserveResult
    valid: bool
    error: str | None = None


def _canonical_attestation_payload(payload: Mapping[str, Any]) -> bytes:
    """Return a deterministic byte representation of the attestation."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_reserve_attestation_signature(
    payload: Mapping[str, Any], secret: str
) -> str:
    """Compute the HMAC-SHA256 signature of ``payload`` with ``secret``.

    Provided as a public helper so trusted upstream attestors (and
    tests) can produce attestations exactly the way the validator
    expects.
    """
    return hmac.new(
        secret.encode("utf-8"),
        _canonical_attestation_payload(payload),
        hashlib.sha256,
    ).hexdigest()


def _coerce_status(raw: Any) -> ReserveStatus | None:
    if raw is None:
        return None
    if isinstance(raw, ReserveStatus):
        return raw
    if isinstance(raw, bool):
        return ReserveStatus.VERIFIED if raw else ReserveStatus.NOT_VERIFIED
    text = str(raw).strip().lower()
    mapping = {
        "verified": ReserveStatus.VERIFIED,
        "true": ReserveStatus.VERIFIED,
        "approved": ReserveStatus.VERIFIED,
        "pass": ReserveStatus.VERIFIED,
        "passed": ReserveStatus.VERIFIED,
        "ok": ReserveStatus.VERIFIED,
        "backed": ReserveStatus.VERIFIED,
        "not_verified": ReserveStatus.NOT_VERIFIED,
        "false": ReserveStatus.NOT_VERIFIED,
        "denied": ReserveStatus.NOT_VERIFIED,
        "fail": ReserveStatus.NOT_VERIFIED,
        "failed": ReserveStatus.NOT_VERIFIED,
        "rejected": ReserveStatus.NOT_VERIFIED,
        "insufficient": ReserveStatus.NOT_VERIFIED,
        "unavailable": ReserveStatus.UNAVAILABLE,
        "unknown": ReserveStatus.UNAVAILABLE,
    }
    return mapping.get(text)


def validate_reserve_attestation(
    *,
    attestation: Mapping[str, Any] | None,
    asset: str,
    trusted_attestors: tuple[str, ...] | list[str],
    secret: str,
    now: int | None = None,
    max_age_seconds: int = DEFAULT_ATTESTATION_MAX_AGE_SECONDS,
) -> AttestationValidationOutcome:
    """Validate a trusted reserve / liquidity attestation.

    The attestation is expected to be a mapping with the following
    shape::

        {
          "attestor": "<trusted-attestor-id>",
          "asset": "<currency-code>",
          "reserve_status":   "verified" | "not_verified" | "unavailable",
          "liquidity_status": "verified" | "not_verified" | "unavailable",
          "checked_at": <unix-seconds>,
          "evidence_reference": "<opaque-id>",
          "reason_codes": ["…"],
          "signature": "<hex-hmac-sha256>"
        }

    Validation rules (all must hold for ``valid=True``):

    * ``trusted_attestors`` and ``secret`` must be configured.
    * The attestation must include an ``attestor`` listed in
      ``trusted_attestors``.
    * The HMAC-SHA256 signature over the canonical-JSON of every other
      field must match ``signature``.
    * The attestation must not be older than ``max_age_seconds``.
    * The attestation's ``asset`` must equal the request ``asset`` (so
      a valid attestation for one currency cannot be replayed for
      another).
    * ``reserve_status`` and ``liquidity_status`` must be recognised
      values.

    On any validation failure the function returns an outcome with
    ``valid=False`` and a normalized :class:`ReserveResult` whose
    statuses are :class:`ReserveStatus.UNAVAILABLE` so the engine can
    fail closed and still record traceable evidence in the proof
    artifact.
    """
    now_ts = int(now if now is not None else time.time())
    base_provider_name = "attestation"

    def _unavailable(error: str, *, attestor: str | None = None) -> AttestationValidationOutcome:
        provider_name = (
            f"{base_provider_name}:{attestor}" if attestor else base_provider_name
        )
        return AttestationValidationOutcome(
            valid=False,
            error=error,
            result=ReserveResult(
                provider_name=provider_name,
                reserve_status=ReserveStatus.UNAVAILABLE,
                liquidity_status=ReserveStatus.UNAVAILABLE,
                evidence_reference=None,
                checked_at=now_ts,
                reason_codes=(error,),
            ),
        )

    if not attestation:
        return _unavailable("RESERVE_ATTESTATION_MISSING")
    if not isinstance(attestation, Mapping):
        return _unavailable("RESERVE_ATTESTATION_MALFORMED")
    if not secret:
        return _unavailable("RESERVE_ATTESTATION_NOT_CONFIGURED")
    trusted = {a.strip() for a in trusted_attestors if isinstance(a, str) and a.strip()}
    if not trusted:
        return _unavailable("RESERVE_ATTESTATION_NOT_CONFIGURED")

    attestor_raw = attestation.get("attestor")
    attestor = str(attestor_raw).strip() if isinstance(attestor_raw, str) else ""
    if not attestor or attestor not in trusted:
        return _unavailable(
            "RESERVE_ATTESTATION_UNTRUSTED_ATTESTOR",
            attestor=attestor or None,
        )

    signature = attestation.get("signature")
    if not isinstance(signature, str) or not signature:
        return _unavailable(
            "RESERVE_ATTESTATION_SIGNATURE_MISSING", attestor=attestor
        )

    payload = {k: v for k, v in attestation.items() if k != "signature"}
    expected = compute_reserve_attestation_signature(payload, secret)
    if not hmac.compare_digest(expected, signature):
        return _unavailable(
            "RESERVE_ATTESTATION_SIGNATURE_INVALID", attestor=attestor
        )

    checked_at_raw = attestation.get("checked_at")
    try:
        checked_at = int(checked_at_raw)
    except (TypeError, ValueError):
        return _unavailable(
            "RESERVE_ATTESTATION_CHECKED_AT_INVALID", attestor=attestor
        )
    if checked_at > now_ts + ATTESTATION_CLOCK_SKEW_MARGIN_SECONDS:
        return _unavailable(
            "RESERVE_ATTESTATION_CHECKED_AT_IN_FUTURE", attestor=attestor
        )
    if (now_ts - checked_at) > max_age_seconds:
        return _unavailable(
            "RESERVE_ATTESTATION_EXPIRED", attestor=attestor
        )

    asserted_asset = attestation.get("asset")
    expected_asset = (asset or "").strip()
    if (
        not isinstance(asserted_asset, str)
        or asserted_asset.strip() != expected_asset
        or not expected_asset
    ):
        return _unavailable(
            "RESERVE_ATTESTATION_ASSET_MISMATCH", attestor=attestor
        )

    reserve_status = _coerce_status(attestation.get("reserve_status"))
    if reserve_status is None:
        return _unavailable(
            "RESERVE_ATTESTATION_RESERVE_STATUS_UNKNOWN", attestor=attestor
        )
    liquidity_status = _coerce_status(attestation.get("liquidity_status"))
    if liquidity_status is None:
        return _unavailable(
            "RESERVE_ATTESTATION_LIQUIDITY_STATUS_UNKNOWN", attestor=attestor
        )

    evidence_reference_raw = attestation.get("evidence_reference")
    evidence_reference = (
        str(evidence_reference_raw).strip()
        if isinstance(evidence_reference_raw, str) and evidence_reference_raw.strip()
        else None
    )

    reason_codes_raw = attestation.get("reason_codes") or ()
    if isinstance(reason_codes_raw, (list, tuple)):
        reason_codes = tuple(
            str(rc).strip() for rc in reason_codes_raw if str(rc).strip()
        )
    else:
        reason_codes = ()
    marker = "RESERVE_EVIDENCE_VIA_ATTESTATION"
    if marker not in reason_codes:
        reason_codes = reason_codes + (marker,)

    return AttestationValidationOutcome(
        valid=True,
        error=None,
        result=ReserveResult(
            provider_name=f"{base_provider_name}:{attestor}",
            reserve_status=reserve_status,
            liquidity_status=liquidity_status,
            evidence_reference=evidence_reference,
            checked_at=checked_at,
            reason_codes=reason_codes,
        ),
    )
