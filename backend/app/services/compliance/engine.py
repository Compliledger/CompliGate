"""Compliance evaluation engine.

This module is the single entry point compliance code paths use to ask
"is this request compliant?". It orchestrates the configured KYC,
sanctions and reserve providers, collects their structured evidence and
turns the combined outcome into a deterministic permit decision.

Policy:

* If **any** required check returns ``denied`` the overall decision is
  ``deny`` with a ``<CHECK>_DENIED`` reason code.
* If **any** required check returns ``unavailable`` (or is not
  configured at all) and ``FAIL_CLOSED_COMPLIANCE`` is ``true`` (the
  default) the overall decision is ``deny`` with a
  ``<CHECK>_PROVIDER_UNAVAILABLE`` reason code – fail-closed so missing
  providers never silently approve a request.
* If ``FAIL_CLOSED_COMPLIANCE`` is explicitly set to ``false``, missing
  or unavailable providers are recorded with a ``<CHECK>_CHECK_SKIPPED``
  reason code and do not block the decision. This mode is only
  intended for narrow local-development scenarios.
* Only when every required check returns ``approved`` (or is skipped
  under fail-open) is the decision ``allow`` and the corresponding
  ``<CHECK>_VERIFIED`` reason codes are emitted.

In addition to the per-check codes above, every KYC evaluation emits a
normalized ``KYC_VERIFIED`` / ``KYC_NOT_VERIFIED`` / ``KYC_UNAVAILABLE``
reason code so callers always receive a stable status token regardless
of provider implementation.

When the action is ``transfer`` and a non-empty ``counterparty`` is
provided, the engine also resolves KYC for the destination using the
configured KYC provider. The destination outcome follows the same
``verified -> continue`` / ``not_verified -> deny`` /
``unavailable -> deny if FAIL_CLOSED_COMPLIANCE=true`` rule logic and
emits ``KYC_DESTINATION_VERIFIED`` / ``KYC_DESTINATION_NOT_VERIFIED`` /
``KYC_DESTINATION_UNAVAILABLE`` reason codes alongside the destination
evidence (persisted with ``check="kyc:destination"``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core import config
from app.services.compliance.providers import (
    ComplianceProvider,
    ProviderResult,
    ProviderStatus,
    get_kyc_provider,
    get_reserve_provider,
    get_sanctions_provider,
)

#: Logical evidence key used for the destination-side KYC evaluation
#: (i.e. the KYC outcome resolved for the transfer counterparty). The
#: subject-side KYC evidence keeps the plain ``"kyc"`` key so existing
#: consumers and tests are unaffected.
KYC_DESTINATION_CHECK = "kyc:destination"

#: Reason code emitted when every required provider returned ``approved``.
APPROVED_REASON_CODES = {
    "kyc": "KYC_VERIFIED",
    "sanctions": "SANCTIONS_PASSED",
    "reserve": "RESERVE_BACKED",
}

#: Reason code emitted when a provider explicitly returned ``denied``.
DENIED_REASON_CODES = {
    "kyc": "KYC_DENIED",
    "sanctions": "SANCTIONS_HIT",
    "reserve": "RESERVE_NOT_VERIFIED",
}

#: Reason code emitted when a provider returned ``unavailable``.
UNAVAILABLE_REASON_CODES = {
    "kyc": "KYC_PROVIDER_UNAVAILABLE",
    "sanctions": "SANCTIONS_PROVIDER_UNAVAILABLE",
    "reserve": "RESERVE_PROVIDER_UNAVAILABLE",
}

#: Reason code emitted when a provider was missing/unavailable but the
#: ``FAIL_CLOSED_COMPLIANCE`` flag was explicitly disabled, so the engine
#: allowed the request anyway. Recorded in the proof artifact so it is
#: always traceable that no real third-party check was performed.
SKIPPED_REASON_CODES = {
    "kyc": "KYC_CHECK_SKIPPED",
    "sanctions": "SANCTIONS_CHECK_SKIPPED",
    "reserve": "RESERVE_CHECK_SKIPPED",
}

#: Normalized KYC reason codes required by the permit-evaluation
#: contract. They are emitted **in addition** to the per-status codes
#: above so callers always get a stable ``KYC_<STATUS>`` token regardless
#: of which provider produced the underlying evidence.
NORMALIZED_KYC_REASON_CODES = {
    ProviderStatus.APPROVED: "KYC_VERIFIED",
    ProviderStatus.DENIED: "KYC_NOT_VERIFIED",
    ProviderStatus.UNAVAILABLE: "KYC_UNAVAILABLE",
}

#: Normalized destination-KYC reason codes. Distinct from the
#: subject-side codes above so consumers can tell which side of the
#: transfer failed compliance.
NORMALIZED_KYC_DESTINATION_REASON_CODES = {
    ProviderStatus.APPROVED: "KYC_DESTINATION_VERIFIED",
    ProviderStatus.DENIED: "KYC_DESTINATION_NOT_VERIFIED",
    ProviderStatus.UNAVAILABLE: "KYC_DESTINATION_UNAVAILABLE",
}

#: Provider-derived sanctions screen reason codes.
#:
#: These are emitted *in addition* to the per-status reason codes above
#: so callers always get an explicit, machine-readable record of the
#: sanctions provider's screen outcome — independent of how the engine
#: collapsed it into the overall decision.  They are required by the
#: permit issuance contract and surfaced in the proof artifact.
SANCTIONS_SCREEN_REASON_CODES = {
    ProviderStatus.APPROVED: "SANCTIONS_SCREEN_PASSED",
    ProviderStatus.DENIED: "SANCTIONS_SCREEN_DENIED",
    ProviderStatus.UNAVAILABLE: "SANCTIONS_SCREEN_UNAVAILABLE",
}


@dataclass(frozen=True)
class ComplianceEvaluation:
    """Aggregated result of all configured compliance providers."""

    decision: str  # "allow" | "deny"
    reason_codes: list[str]
    evidence: list[dict[str, Any]]
    results: dict[str, ProviderResult] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    def status_for(self, check: str) -> ProviderStatus | None:
        result = self.results.get(check)
        return result.status if result is not None else None

    def reference_for(self, check: str) -> str | None:
        result = self.results.get(check)
        return result.reference if result is not None else None


def _default_providers() -> dict[str, ComplianceProvider]:
    return {
        "kyc": get_kyc_provider(),
        "sanctions": get_sanctions_provider(),
        "reserve": get_reserve_provider(),
    }


def evaluate_compliance(
    *,
    subject: str,
    action: str,
    amount: float | int | None,
    counterparty: str | None,
    asset: dict[str, Any] | None = None,
    providers: dict[str, ComplianceProvider] | None = None,
    kyc_assertion: dict[str, Any] | None = None,
) -> ComplianceEvaluation:
    """Run every configured compliance provider and aggregate results.

    The function is pure with respect to ``providers`` – tests inject a
    custom mapping to exercise allow / deny / unavailable paths
    deterministically.

    ``kyc_assertion`` is an optional trusted upstream KYC payload (see
    :mod:`app.services.compliance.kyc`) that the ``upstream_assertion``
    KYC provider validates against the configured shared secret and
    issuer allowlist. Other providers ignore it.
    """
    providers = providers or _default_providers()
    fail_closed = bool(config.FAIL_CLOSED_COMPLIANCE)
    context: dict[str, Any] = {
        "subject": subject,
        "action": action,
        "amount": amount,
        "counterparty": counterparty,
        "asset": asset or {},
        "kyc_assertion": kyc_assertion,
    }

    reason_codes: list[str] = []
    evidence: list[dict[str, Any]] = []
    results: dict[str, ProviderResult] = {}
    decision = "allow"

    # Iterate in a fixed order so reason codes are deterministic and the
    # proof artifact is reproducible across runs.
    for check in ("kyc", "sanctions", "reserve"):
        provider = providers.get(check)
        if provider is None:
            # Treat missing providers exactly like unavailable ones:
            # fail closed with a traceable reason code unless
            # FAIL_CLOSED_COMPLIANCE has been explicitly disabled.
            if fail_closed:
                reason_codes.append(UNAVAILABLE_REASON_CODES[check])
                decision = "deny"
            else:
                reason_codes.append(SKIPPED_REASON_CODES[check])
            if check == "sanctions":
                # Always surface a provider-derived screen reason code
                # so the permit response and proof artifact record the
                # sanctions outcome explicitly, even when no provider
                # was registered.
                reason_codes.append(
                    SANCTIONS_SCREEN_REASON_CODES[ProviderStatus.UNAVAILABLE]
                )
            if check == "kyc":
                # Always surface a normalized KYC_<STATUS> code so the
                # permit response carries the required vocabulary even
                # when no provider was registered.
                normalized = NORMALIZED_KYC_REASON_CODES[ProviderStatus.UNAVAILABLE]
                if normalized not in reason_codes:
                    reason_codes.append(normalized)
            evidence.append(
                {
                    "check": check,
                    "status": ProviderStatus.UNAVAILABLE.value,
                    "provider_id": f"missing:{check}",
                    "reference": None,
                    "reason": "provider_not_registered",
                    "checked_at": 0,
                    "details": {"fail_closed": fail_closed},
                }
            )
            continue

        result = provider.evaluate(context)
        results[check] = result
        evidence.append(result.to_evidence())

        if result.status is ProviderStatus.APPROVED:
            reason_codes.append(APPROVED_REASON_CODES[check])
        elif result.status is ProviderStatus.DENIED:
            # An explicit denial is always honored regardless of the
            # FAIL_CLOSED_COMPLIANCE flag.
            reason_codes.append(DENIED_REASON_CODES[check])
            decision = "deny"
        else:  # ProviderStatus.UNAVAILABLE
            if fail_closed:
                reason_codes.append(UNAVAILABLE_REASON_CODES[check])
                decision = "deny"
            else:
                reason_codes.append(SKIPPED_REASON_CODES[check])

        if check == "sanctions":
            screen_code = SANCTIONS_SCREEN_REASON_CODES.get(result.status)
            if screen_code is not None:
                reason_codes.append(screen_code)
        if check == "kyc":
            normalized = NORMALIZED_KYC_REASON_CODES.get(result.status)
            if normalized is not None and normalized not in reason_codes:
                reason_codes.append(normalized)

    # Resolve destination-side KYC when applicable. We re-use the
    # configured KYC provider with a context whose ``subject`` is the
    # counterparty so the same fail-closed semantics, evidence shape and
    # normalized KycResult apply to the destination side of the
    # transfer. Destination KYC is only meaningful when the action moves
    # value to a counterparty: ``transfer`` with a non-empty
    # counterparty. ``trustset`` and counterparty-less actions skip it.
    destination = (counterparty or "").strip() if isinstance(counterparty, str) else ""
    if action == "transfer" and destination:
        kyc_provider = providers.get("kyc")
        destination_context = dict(context)
        destination_context["subject"] = destination
        destination_context["kyc_subject_role"] = "destination"
        # The trusted-upstream KYC assertion is bound to the request
        # subject, so it must not be re-used to satisfy the
        # destination-side check.
        destination_context["kyc_assertion"] = None

        if kyc_provider is None:
            if fail_closed:
                reason_codes.append("KYC_DESTINATION_PROVIDER_UNAVAILABLE")
                decision = "deny"
            else:
                reason_codes.append("KYC_DESTINATION_CHECK_SKIPPED")
            reason_codes.append(
                NORMALIZED_KYC_DESTINATION_REASON_CODES[ProviderStatus.UNAVAILABLE]
            )
            evidence.append(
                {
                    "check": KYC_DESTINATION_CHECK,
                    "status": ProviderStatus.UNAVAILABLE.value,
                    "provider_id": "missing:kyc:destination",
                    "reference": None,
                    "reason": "provider_not_registered",
                    "checked_at": 0,
                    "details": {
                        "fail_closed": fail_closed,
                        "subject_role": "destination",
                    },
                }
            )
        else:
            destination_result = kyc_provider.evaluate(destination_context)
            # Tag the persisted evidence with the destination role and
            # the destination-scoped check key so consumers can tell
            # subject- and destination-side KYC apart in the proof
            # artifact.
            destination_evidence = destination_result.to_evidence()
            destination_evidence["check"] = KYC_DESTINATION_CHECK
            details = dict(destination_evidence.get("details") or {})
            details["subject_role"] = "destination"
            destination_evidence["details"] = details
            results[KYC_DESTINATION_CHECK] = destination_result
            evidence.append(destination_evidence)

            if destination_result.status is ProviderStatus.APPROVED:
                reason_codes.append("KYC_DESTINATION_APPROVED")
            elif destination_result.status is ProviderStatus.DENIED:
                reason_codes.append("KYC_DESTINATION_DENIED")
                decision = "deny"
            else:  # ProviderStatus.UNAVAILABLE
                if fail_closed:
                    reason_codes.append("KYC_DESTINATION_PROVIDER_UNAVAILABLE")
                    decision = "deny"
                else:
                    reason_codes.append("KYC_DESTINATION_CHECK_SKIPPED")

            normalized_destination = NORMALIZED_KYC_DESTINATION_REASON_CODES.get(
                destination_result.status
            )
            if normalized_destination is not None:
                reason_codes.append(normalized_destination)

    return ComplianceEvaluation(
        decision=decision,
        reason_codes=reason_codes,
        evidence=evidence,
        results=results,
    )
