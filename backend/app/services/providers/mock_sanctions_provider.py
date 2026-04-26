"""Mock sanctions provider that simulates realistic screening outcomes.

This implementation is intentionally **not** a real TRM (or any other
vendor) integration.  It exists so local development, demos and tests can
exercise the full sanctions screening code path without standing up an
actual provider.  The decision is derived from the literal contents of the
screened address so callers can deterministically simulate the three
outcomes the policy engine cares about: ``pass``, ``deny`` and
``unavailable``.

The provider implements the vendor-neutral
:class:`~app.services.providers.sanctions_provider.SanctionsProvider`
interface and returns the same normalized
:class:`~app.services.providers.base.ProviderResult` shape as the
production HTTP-backed provider.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from app.services.providers.base import (
    ProviderDecision,
    ProviderResult,
    ProviderStatus,
)
from app.services.providers.sanctions_provider import SanctionsProvider

#: Reason code emitted when the simulated address contains "SANCTIONED".
SANCTIONS_MATCH_REASON = "SANCTIONS_MATCH"

#: Reason code emitted when the simulated address contains "REVIEW",
#: i.e. the mock pretends the upstream provider is temporarily unavailable.
PROVIDER_UNAVAILABLE_SIMULATED_REASON = "PROVIDER_UNAVAILABLE_SIMULATED"

#: Reason code emitted on the default ("clean") simulated outcome.
SANCTIONS_SCREEN_PASSED_REASON = "SANCTIONS_SCREEN_PASSED"


class MockSanctionsProvider(SanctionsProvider):
    """Simulated sanctions provider used for local development and tests.

    Behavior is driven entirely by the address being screened:

    * If the address contains the substring ``"SANCTIONED"`` the provider
      returns ``decision=DENY`` with reason code ``SANCTIONS_MATCH``.
    * If the address contains the substring ``"REVIEW"`` the provider
      returns ``decision=UNAVAILABLE`` with reason code
      ``PROVIDER_UNAVAILABLE_SIMULATED`` to simulate the upstream vendor
      being temporarily unreachable.
    * Otherwise the provider returns ``decision=PASS`` with reason code
      ``SANCTIONS_SCREEN_PASSED``.

    The provider is **always** considered configured: it has no external
    dependencies and never makes a network call.  It must not be used in
    production — the metadata explicitly flags the result as a mock.
    """

    provider_name = "mock_trm"

    def is_configured(self) -> bool:
        # The mock has no configuration to validate; it is always usable.
        return True

    def screen(
        self,
        *,
        subject: str,
        context: Mapping[str, Any] | None = None,
    ) -> ProviderResult:
        address = subject
        decision, reason_code = self._classify(address)

        # Capture a single timestamp so ``checked_at`` and the timestamp
        # embedded in ``evidence_reference`` stay consistent.
        checked_at = datetime.now(timezone.utc)
        timestamp = checked_at.isoformat()

        metadata: dict[str, Any] = {
            "mode": "mock",
            "note": "TRM integration pending",
        }

        return ProviderResult(
            provider_name=self.provider_name,
            status=ProviderStatus.OK,
            decision=decision,
            reason_codes=(reason_code,),
            evidence_reference=f"mock:{address}:{timestamp}",
            checked_at=checked_at,
            raw_response_excerpt=metadata,
        )

    @staticmethod
    def _classify(address: str) -> tuple[ProviderDecision, str]:
        """Map an address to a simulated (decision, reason_code) pair.

        The order matters: ``SANCTIONED`` is checked before ``REVIEW`` so
        an address containing both substrings is treated as a hard deny
        rather than a soft "needs review" outcome.
        """

        if "SANCTIONED" in address:
            return ProviderDecision.DENY, SANCTIONS_MATCH_REASON
        if "REVIEW" in address:
            return ProviderDecision.UNAVAILABLE, PROVIDER_UNAVAILABLE_SIMULATED_REASON
        return ProviderDecision.PASS, SANCTIONS_SCREEN_PASSED_REASON


__all__ = [
    "MockSanctionsProvider",
    "SANCTIONS_MATCH_REASON",
    "PROVIDER_UNAVAILABLE_SIMULATED_REASON",
    "SANCTIONS_SCREEN_PASSED_REASON",
]
