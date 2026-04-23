"""Normalized KYC result and trusted-upstream-assertion validation.

CompliGate is an authorization layer; it does not invent KYC state. KYC
evidence reaches the compliance engine through one of two supported paths:

1. **Direct KYC provider integration** — a real third-party identity
   verification service is called over HTTPS (see the ``http`` KYC
   provider kind in :mod:`app.services.compliance.providers`).
2. **Trusted upstream assertion from a verified institutional system** —
   an upstream institution (custodian, broker-dealer, etc.) that has
   already performed KYC submits a signed assertion alongside the permit
   request. The assertion is verified against a configured HMAC shared
   secret and an allowlist of trusted issuer identifiers.

In both cases the engine surfaces a single normalized
:class:`KycResult` so downstream consumers (permit bundle, proof
artifact, audit logs) never have to reason about provider-specific
shapes — and KYC outcomes are *always* derived from real evidence.

When neither path is configured (or the assertion is missing/invalid)
the engine falls back to its fail-closed policy and denies the request
with a ``KYC_PROVIDER_UNAVAILABLE`` reason code as long as
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


class KycStatus(str, Enum):
    """Normalized KYC outcome.

    The vocabulary is intentionally narrower than the engine-level
    :class:`~app.services.compliance.providers.ProviderStatus` (which
    also carries an explicit ``denied`` value used for hard failures
    other than identity-verification). For KYC the meaningful outcomes
    are: the subject **is** verified, the subject **is not** verified,
    or no usable evidence is available.
    """

    VERIFIED = "verified"
    NOT_VERIFIED = "not_verified"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class KycResult:
    """Normalized, persistable KYC evidence.

    The shape is identical regardless of whether the result came from a
    direct provider integration or a trusted upstream assertion, so the
    bundle / proof artifact never has to special-case the source.

    Attributes:
        provider_name: Stable identifier of the KYC source. Either the
            configured KYC provider name (``"http:kyc"``,
            ``"static_allow:kyc"``, …) or the upstream issuer identifier
            (``"upstream_assertion:<issuer>"``) when the result came
            from a trusted institutional assertion. Aliased as
            ``source_system`` via :attr:`source_system` for callers who
            prefer that name.
        subject_id: Subject the KYC outcome was issued for. For wallet
            bindings this is the XRPL classic address; for customer-id
            bindings it is the upstream identifier. The engine
            cross-checks this against the request subject so an
            assertion for one wallet cannot be replayed for another.
        kyc_status: Normalized outcome — ``verified`` / ``not_verified``
            / ``unavailable``.
        jurisdiction: Jurisdiction the KYC programme covers (e.g.
            ``"US"``). Empty string when the source did not specify
            one.
        checked_at: UNIX timestamp (seconds) of when the underlying
            check was performed by the source system.
        evidence_reference: Optional external reference (case id,
            document hash, signed-assertion id) auditors can use to
            retrieve the original evidence.
        reason_codes: Machine-readable reason codes that justify the
            outcome. Always upper-snake-case, ordered most- to
            least-significant.
    """

    provider_name: str
    subject_id: str
    kyc_status: KycStatus
    jurisdiction: str = ""
    checked_at: int = field(default_factory=lambda: int(time.time()))
    evidence_reference: str | None = None
    reason_codes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def source_system(self) -> str:
        """Alias of :attr:`provider_name`.

        The requirement language uses ``provider_name`` for direct
        integrations and ``source_system`` for upstream assertions; we
        keep a single underlying field and expose both names so callers
        can use whichever fits their domain language.
        """
        return self.provider_name

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""
        return {
            "provider_name": self.provider_name,
            "source_system": self.provider_name,
            "subject_id": self.subject_id,
            "kyc_status": self.kyc_status.value,
            "jurisdiction": self.jurisdiction,
            "checked_at": self.checked_at,
            "evidence_reference": self.evidence_reference,
            "reason_codes": list(self.reason_codes),
        }


# ---------------------------------------------------------------------------
# Trusted upstream assertion validation
# ---------------------------------------------------------------------------

#: Maximum age of a valid upstream assertion in seconds. Assertions older
#: than this are rejected so a leaked signed payload cannot be replayed
#: indefinitely.
DEFAULT_ASSERTION_MAX_AGE_SECONDS = 24 * 60 * 60  # 24h

#: Tolerated clock skew between the upstream issuer and CompliGate when
#: validating ``checked_at``. Anything beyond this margin in the future
#: is treated as a forged / misconfigured assertion.
ASSERTION_CLOCK_SKEW_MARGIN_SECONDS = 60


@dataclass(frozen=True)
class AssertionValidationOutcome:
    """Outcome of validating a trusted upstream KYC assertion."""

    result: KycResult
    valid: bool
    error: str | None = None


def _canonical_assertion_payload(payload: Mapping[str, Any]) -> bytes:
    """Return a deterministic byte representation of the assertion.

    Sorting keys and using a compact separator gives us a canonical
    form that both signer and verifier compute identically regardless
    of dict iteration order.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_assertion_signature(payload: Mapping[str, Any], secret: str) -> str:
    """Compute the HMAC-SHA256 signature of ``payload`` with ``secret``.

    Provided as a public helper so trusted upstream issuers (and tests)
    can produce assertions exactly the way the validator expects.
    """
    return hmac.new(
        secret.encode("utf-8"),
        _canonical_assertion_payload(payload),
        hashlib.sha256,
    ).hexdigest()


def _coerce_status(raw: Any) -> KycStatus | None:
    if raw is None:
        return None
    if isinstance(raw, KycStatus):
        return raw
    text = str(raw).strip().lower()
    mapping = {
        "verified": KycStatus.VERIFIED,
        "true": KycStatus.VERIFIED,
        "approved": KycStatus.VERIFIED,
        "pass": KycStatus.VERIFIED,
        "passed": KycStatus.VERIFIED,
        "not_verified": KycStatus.NOT_VERIFIED,
        "false": KycStatus.NOT_VERIFIED,
        "denied": KycStatus.NOT_VERIFIED,
        "fail": KycStatus.NOT_VERIFIED,
        "failed": KycStatus.NOT_VERIFIED,
        "rejected": KycStatus.NOT_VERIFIED,
        "unavailable": KycStatus.UNAVAILABLE,
        "unknown": KycStatus.UNAVAILABLE,
    }
    return mapping.get(text)


def validate_upstream_assertion(
    *,
    assertion: Mapping[str, Any] | None,
    subject: str,
    trusted_issuers: tuple[str, ...] | list[str],
    secret: str,
    now: int | None = None,
    max_age_seconds: int = DEFAULT_ASSERTION_MAX_AGE_SECONDS,
) -> AssertionValidationOutcome:
    """Validate a trusted upstream KYC assertion.

    The assertion is expected to be a mapping with the following shape::

        {
          "issuer": "<trusted-institution-id>",
          "subject_id": "<wallet or customer id>",
          "kyc_status": "verified" | "not_verified" | "unavailable",
          "jurisdiction": "US",
          "checked_at": <unix-seconds>,
          "evidence_reference": "<opaque-id>",
          "reason_codes": ["…"],
          "signature": "<hex-hmac-sha256>"
        }

    Validation rules (all must hold for ``valid=True``):

    * ``trusted_issuers`` and ``secret`` must be configured.
    * The assertion must include an ``issuer`` listed in
      ``trusted_issuers``.
    * The HMAC-SHA256 signature over the canonical-JSON of every other
      field must match ``signature``.
    * The assertion must not be older than ``max_age_seconds``.
    * The assertion's ``subject_id`` must equal the request ``subject``
      (so a valid assertion can never be replayed for a different
      wallet).
    * ``kyc_status`` must be a recognised value.

    On any validation failure the function returns an outcome with
    ``valid=False`` and a normalized :class:`KycResult` whose status is
    :class:`KycStatus.UNAVAILABLE` so the engine can fail closed and
    still record traceable evidence in the proof artifact.
    """
    now_ts = int(now if now is not None else time.time())

    base_provider_name = "upstream_assertion"

    def _unavailable(error: str, *, issuer: str | None = None) -> AssertionValidationOutcome:
        provider_name = (
            f"{base_provider_name}:{issuer}" if issuer else base_provider_name
        )
        return AssertionValidationOutcome(
            valid=False,
            error=error,
            result=KycResult(
                provider_name=provider_name,
                subject_id=subject,
                kyc_status=KycStatus.UNAVAILABLE,
                jurisdiction="",
                checked_at=now_ts,
                evidence_reference=None,
                reason_codes=(error,),
            ),
        )

    if not assertion:
        return _unavailable("KYC_UPSTREAM_ASSERTION_MISSING")
    if not isinstance(assertion, Mapping):
        return _unavailable("KYC_UPSTREAM_ASSERTION_MALFORMED")
    if not secret:
        return _unavailable("KYC_UPSTREAM_ASSERTION_NOT_CONFIGURED")
    trusted = {i.strip() for i in trusted_issuers if isinstance(i, str) and i.strip()}
    if not trusted:
        return _unavailable("KYC_UPSTREAM_ASSERTION_NOT_CONFIGURED")

    issuer_raw = assertion.get("issuer")
    issuer = str(issuer_raw).strip() if isinstance(issuer_raw, str) else ""
    if not issuer or issuer not in trusted:
        return _unavailable(
            "KYC_UPSTREAM_ASSERTION_UNTRUSTED_ISSUER",
            issuer=issuer or None,
        )

    signature = assertion.get("signature")
    if not isinstance(signature, str) or not signature:
        return _unavailable(
            "KYC_UPSTREAM_ASSERTION_SIGNATURE_MISSING", issuer=issuer
        )

    payload = {k: v for k, v in assertion.items() if k != "signature"}
    expected = compute_assertion_signature(payload, secret)
    if not hmac.compare_digest(expected, signature):
        return _unavailable(
            "KYC_UPSTREAM_ASSERTION_SIGNATURE_INVALID", issuer=issuer
        )

    checked_at_raw = assertion.get("checked_at")
    try:
        checked_at = int(checked_at_raw)
    except (TypeError, ValueError):
        return _unavailable(
            "KYC_UPSTREAM_ASSERTION_CHECKED_AT_INVALID", issuer=issuer
        )
    if checked_at > now_ts + ASSERTION_CLOCK_SKEW_MARGIN_SECONDS:
        # Allow a tiny clock-skew margin but reject obviously
        # future-dated assertions.
        return _unavailable(
            "KYC_UPSTREAM_ASSERTION_CHECKED_AT_IN_FUTURE", issuer=issuer
        )
    if (now_ts - checked_at) > max_age_seconds:
        return _unavailable(
            "KYC_UPSTREAM_ASSERTION_EXPIRED", issuer=issuer
        )

    asserted_subject = assertion.get("subject_id")
    if not isinstance(asserted_subject, str) or asserted_subject.strip() != subject:
        return _unavailable(
            "KYC_UPSTREAM_ASSERTION_SUBJECT_MISMATCH", issuer=issuer
        )

    kyc_status = _coerce_status(assertion.get("kyc_status"))
    if kyc_status is None:
        return _unavailable(
            "KYC_UPSTREAM_ASSERTION_STATUS_UNKNOWN", issuer=issuer
        )

    jurisdiction_raw = assertion.get("jurisdiction") or ""
    jurisdiction = str(jurisdiction_raw).strip()

    evidence_reference_raw = assertion.get("evidence_reference")
    evidence_reference = (
        str(evidence_reference_raw).strip()
        if isinstance(evidence_reference_raw, str) and evidence_reference_raw.strip()
        else None
    )

    reason_codes_raw = assertion.get("reason_codes") or ()
    if isinstance(reason_codes_raw, (list, tuple)):
        reason_codes = tuple(
            str(rc).strip() for rc in reason_codes_raw if str(rc).strip()
        )
    else:
        reason_codes = ()
    # Always carry an explicit "verified-via-upstream" marker so audit
    # tooling can distinguish the source without having to inspect
    # ``provider_name``.
    if kyc_status is KycStatus.VERIFIED:
        marker = "KYC_VERIFIED_VIA_UPSTREAM_ASSERTION"
    elif kyc_status is KycStatus.NOT_VERIFIED:
        marker = "KYC_NOT_VERIFIED_VIA_UPSTREAM_ASSERTION"
    else:
        marker = "KYC_UNAVAILABLE_VIA_UPSTREAM_ASSERTION"
    if marker not in reason_codes:
        reason_codes = reason_codes + (marker,)

    return AssertionValidationOutcome(
        valid=True,
        error=None,
        result=KycResult(
            provider_name=f"{base_provider_name}:{issuer}",
            subject_id=subject,
            kyc_status=kyc_status,
            jurisdiction=jurisdiction,
            checked_at=checked_at,
            evidence_reference=evidence_reference,
            reason_codes=reason_codes,
        ),
    )
