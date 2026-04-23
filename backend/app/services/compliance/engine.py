"""Compliance evaluation engine.

This module is the single entry point compliance code paths use to ask
"is this request compliant?". It orchestrates the configured KYC,
sanctions and reserve providers, collects their structured evidence and
turns the combined outcome into a deterministic permit decision.

Policy:

* If **any** required check returns ``denied`` the overall decision is
  ``deny`` with a ``<CHECK>_DENIED`` reason code.
* If **any** required check returns ``unavailable`` the overall decision
  is ``deny`` with a ``<CHECK>_PROVIDER_UNAVAILABLE`` reason code –
  fail-closed so missing providers never silently approve a request.
* Only when every required check returns ``approved`` is the decision
  ``allow`` and the corresponding ``<CHECK>_VERIFIED`` reason codes are
  emitted.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.compliance.providers import (
    ComplianceProvider,
    ProviderResult,
    ProviderStatus,
    get_kyc_provider,
    get_reserve_provider,
    get_sanctions_provider,
)

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
) -> ComplianceEvaluation:
    """Run every configured compliance provider and aggregate results.

    The function is pure with respect to ``providers`` – tests inject a
    custom mapping to exercise allow / deny / unavailable paths
    deterministically.
    """
    providers = providers or _default_providers()
    context: dict[str, Any] = {
        "subject": subject,
        "action": action,
        "amount": amount,
        "counterparty": counterparty,
        "asset": asset or {},
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
            # fail closed with a traceable reason code.
            reason_codes.append(UNAVAILABLE_REASON_CODES[check])
            evidence.append(
                {
                    "check": check,
                    "status": ProviderStatus.UNAVAILABLE.value,
                    "provider_id": f"missing:{check}",
                    "reference": None,
                    "reason": "provider_not_registered",
                    "checked_at": 0,
                    "details": {},
                }
            )
            decision = "deny"
            continue

        result = provider.evaluate(context)
        results[check] = result
        evidence.append(result.to_evidence())

        if result.status is ProviderStatus.APPROVED:
            reason_codes.append(APPROVED_REASON_CODES[check])
        elif result.status is ProviderStatus.DENIED:
            reason_codes.append(DENIED_REASON_CODES[check])
            decision = "deny"
        else:  # ProviderStatus.UNAVAILABLE
            reason_codes.append(UNAVAILABLE_REASON_CODES[check])
            decision = "deny"

    return ComplianceEvaluation(
        decision=decision,
        reason_codes=reason_codes,
        evidence=evidence,
        results=results,
    )
