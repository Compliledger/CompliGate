"""Provider-backed compliance checks.

CompliGate is an authorization / verification layer. It does not invent
compliance state; it asks configured providers (KYC, sanctions, reserve)
for evidence and records what they returned. When no provider is
configured, the default behaviour is to fail closed (the request is
denied with an explicit ``*_PROVIDER_UNAVAILABLE`` reason code) so that
no compliance decision is ever fabricated.
"""

from app.services.compliance.engine import (
    ComplianceEvaluation,
    evaluate_compliance,
)
from app.services.compliance.kyc import (
    AssertionValidationOutcome,
    KycResult,
    KycStatus,
    compute_assertion_signature,
    validate_upstream_assertion,
)
from app.services.compliance.providers import (
    ComplianceProvider,
    ProviderResult,
    ProviderStatus,
    get_kyc_provider,
    get_reserve_provider,
    get_sanctions_provider,
)

__all__ = [
    "AssertionValidationOutcome",
    "ComplianceEvaluation",
    "ComplianceProvider",
    "KycResult",
    "KycStatus",
    "ProviderResult",
    "ProviderStatus",
    "compute_assertion_signature",
    "evaluate_compliance",
    "get_kyc_provider",
    "get_reserve_provider",
    "get_sanctions_provider",
    "validate_upstream_assertion",
]
