"""Provider-backed compliance tests.

These tests cover the real ``evaluate_compliance`` and ``/v1/permit``
code paths end-to-end, using *mock* :class:`ComplianceProvider`
implementations instead of stubbed booleans so the engine's reason
codes, evidence aggregation, fail-closed policy and proof-artifact
wiring are all exercised the same way they would be in production.

Each ``_Mock*Provider`` below is a fully-fledged provider that returns a
real :class:`ProviderResult`; the engine then converts the result into
evidence and reason codes exactly as it does for the built-in HTTP /
upstream-assertion providers.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.core import config
from app.main import app
from app.services.compliance import (
    ProviderResult,
    ProviderStatus,
    evaluate_compliance,
)
from app.services.compliance.providers import ComplianceProvider

VALID_SUBJECT = "rN7n3473SaZBCG4dFL83w7PB5XDnEHyMQX"

client = TestClient(app)


# ---------------------------------------------------------------------------
# Mock providers
#
# These are real ``ComplianceProvider`` subclasses (not stubbed booleans).
# The engine invokes ``evaluate`` and persists the returned
# ``ProviderResult.to_evidence()`` exactly as it would for any production
# provider, so the compliance code path is fully exercised.
# ---------------------------------------------------------------------------


class _MockProvider(ComplianceProvider):
    """Configurable mock provider that returns a fixed ``ProviderResult``."""

    kind = "mock"

    def __init__(
        self,
        check: str,
        status: ProviderStatus,
        *,
        reference: str | None = None,
        reason: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.check = check
        self._status = status
        self._reference = reference
        self._reason = reason
        self._details = details or {}
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, context: dict[str, Any]) -> ProviderResult:
        # Record that we were invoked so tests can assert the engine
        # actually walked the provider code path rather than short-
        # circuiting to a hard-coded boolean.
        self.calls.append(dict(context))
        return ProviderResult(
            check=self.check,
            status=self._status,
            provider_id=f"mock:{self.check}",
            reference=self._reference,
            reason=self._reason,
            details=dict(self._details),
        )


def _approved_providers() -> dict[str, _MockProvider]:
    """Return a baseline of approved mock providers for KYC/sanctions/reserve."""
    return {
        "kyc": _MockProvider(
            "kyc",
            ProviderStatus.APPROVED,
            reference="kyc-ref-1",
            reason="kyc_verified",
        ),
        "sanctions": _MockProvider(
            "sanctions",
            ProviderStatus.APPROVED,
            reference="sanctions-ref-1",
            reason="no_match",
        ),
        "reserve": _MockProvider(
            "reserve",
            ProviderStatus.APPROVED,
            reference="reserve-ref-1",
            reason="reserve_backed",
        ),
    }


# ---------------------------------------------------------------------------
# 1. Sanctions provider pass
# ---------------------------------------------------------------------------


def test_sanctions_provider_pass_allows_and_emits_screen_passed():
    providers = _approved_providers()
    evaluation = evaluate_compliance(
        subject=VALID_SUBJECT,
        action="transfer",
        amount=10,
        counterparty=None,
        providers=providers,
    )

    assert evaluation.decision == "allow"
    # Both the legacy and provider-derived screen reason codes are surfaced.
    assert "SANCTIONS_PASSED" in evaluation.reason_codes
    assert "SANCTIONS_SCREEN_PASSED" in evaluation.reason_codes
    assert "SANCTIONS_HIT" not in evaluation.reason_codes
    assert "SANCTIONS_SCREEN_DENIED" not in evaluation.reason_codes

    sanctions_evidence = next(
        item for item in evaluation.evidence if item["check"] == "sanctions"
    )
    assert sanctions_evidence["status"] == ProviderStatus.APPROVED.value
    assert sanctions_evidence["provider_id"] == "mock:sanctions"
    assert sanctions_evidence["reference"] == "sanctions-ref-1"

    # Engine actually invoked the provider — the code path is real.
    assert providers["sanctions"].calls, "sanctions provider was not invoked"


# ---------------------------------------------------------------------------
# 2. Sanctions provider deny
# ---------------------------------------------------------------------------


def test_sanctions_provider_deny_blocks_and_emits_screen_denied():
    providers = _approved_providers()
    providers["sanctions"] = _MockProvider(
        "sanctions",
        ProviderStatus.DENIED,
        reference="sanctions-case-42",
        reason="ofac_match",
    )

    evaluation = evaluate_compliance(
        subject=VALID_SUBJECT,
        action="transfer",
        amount=10,
        counterparty=None,
        providers=providers,
    )

    assert evaluation.decision == "deny"
    assert "SANCTIONS_HIT" in evaluation.reason_codes
    assert "SANCTIONS_SCREEN_DENIED" in evaluation.reason_codes
    assert "SANCTIONS_PASSED" not in evaluation.reason_codes
    sanctions_evidence = next(
        item for item in evaluation.evidence if item["check"] == "sanctions"
    )
    assert sanctions_evidence["status"] == ProviderStatus.DENIED.value
    assert sanctions_evidence["reference"] == "sanctions-case-42"
    assert sanctions_evidence["reason"] == "ofac_match"


# ---------------------------------------------------------------------------
# 3. Sanctions provider unavailable + fail-closed
# ---------------------------------------------------------------------------


def test_sanctions_provider_unavailable_fail_closed_denies():
    providers = _approved_providers()
    providers["sanctions"] = _MockProvider(
        "sanctions",
        ProviderStatus.UNAVAILABLE,
        reason="provider_request_failed",
    )

    with patch.object(config, "FAIL_CLOSED_COMPLIANCE", True):
        evaluation = evaluate_compliance(
            subject=VALID_SUBJECT,
            action="transfer",
            amount=10,
            counterparty=None,
            providers=providers,
        )

    assert evaluation.decision == "deny"
    assert "SANCTIONS_PROVIDER_UNAVAILABLE" in evaluation.reason_codes
    assert "SANCTIONS_SCREEN_UNAVAILABLE" in evaluation.reason_codes
    sanctions_evidence = next(
        item for item in evaluation.evidence if item["check"] == "sanctions"
    )
    assert sanctions_evidence["status"] == ProviderStatus.UNAVAILABLE.value
    assert sanctions_evidence["reason"] == "provider_request_failed"


# ---------------------------------------------------------------------------
# 4. KYC verified
# ---------------------------------------------------------------------------


def test_kyc_verified_emits_normalized_and_legacy_codes():
    providers = _approved_providers()
    evaluation = evaluate_compliance(
        subject=VALID_SUBJECT,
        action="transfer",
        amount=10,
        counterparty=None,
        providers=providers,
    )

    assert evaluation.decision == "allow"
    assert "KYC_VERIFIED" in evaluation.reason_codes
    assert "KYC_NOT_VERIFIED" not in evaluation.reason_codes
    assert "KYC_UNAVAILABLE" not in evaluation.reason_codes

    kyc_evidence = next(
        item for item in evaluation.evidence if item["check"] == "kyc"
    )
    assert kyc_evidence["status"] == ProviderStatus.APPROVED.value
    assert kyc_evidence["provider_id"] == "mock:kyc"
    assert kyc_evidence["reference"] == "kyc-ref-1"


# ---------------------------------------------------------------------------
# 5. KYC not verified
# ---------------------------------------------------------------------------


def test_kyc_not_verified_blocks_and_emits_kyc_not_verified():
    providers = _approved_providers()
    providers["kyc"] = _MockProvider(
        "kyc",
        ProviderStatus.DENIED,
        reference="kyc-case-7",
        reason="document_rejected",
    )

    evaluation = evaluate_compliance(
        subject=VALID_SUBJECT,
        action="transfer",
        amount=10,
        counterparty=None,
        providers=providers,
    )

    assert evaluation.decision == "deny"
    assert "KYC_DENIED" in evaluation.reason_codes
    assert "KYC_NOT_VERIFIED" in evaluation.reason_codes
    assert "KYC_VERIFIED" not in evaluation.reason_codes

    kyc_evidence = next(
        item for item in evaluation.evidence if item["check"] == "kyc"
    )
    assert kyc_evidence["status"] == ProviderStatus.DENIED.value
    assert kyc_evidence["reason"] == "document_rejected"
    assert kyc_evidence["reference"] == "kyc-case-7"


# ---------------------------------------------------------------------------
# 6. KYC unavailable + fail-closed
# ---------------------------------------------------------------------------


def test_kyc_unavailable_fail_closed_denies():
    providers = _approved_providers()
    providers["kyc"] = _MockProvider(
        "kyc",
        ProviderStatus.UNAVAILABLE,
        reason="provider_request_failed",
    )

    with patch.object(config, "FAIL_CLOSED_COMPLIANCE", True):
        evaluation = evaluate_compliance(
            subject=VALID_SUBJECT,
            action="transfer",
            amount=10,
            counterparty=None,
            providers=providers,
        )

    assert evaluation.decision == "deny"
    assert "KYC_PROVIDER_UNAVAILABLE" in evaluation.reason_codes
    assert "KYC_UNAVAILABLE" in evaluation.reason_codes
    assert "KYC_VERIFIED" not in evaluation.reason_codes

    kyc_evidence = next(
        item for item in evaluation.evidence if item["check"] == "kyc"
    )
    assert kyc_evidence["status"] == ProviderStatus.UNAVAILABLE.value


# ---------------------------------------------------------------------------
# 7. Reserve verified
# ---------------------------------------------------------------------------


def test_reserve_verified_emits_reserve_and_liquidity_codes():
    providers = _approved_providers()
    evaluation = evaluate_compliance(
        subject=VALID_SUBJECT,
        action="transfer",
        amount=10,
        counterparty=None,
        asset={"classification": "regulated_stablecoin"},
        providers=providers,
    )

    assert evaluation.decision == "allow"
    assert "RESERVE_BACKED" in evaluation.reason_codes
    assert "RESERVE_VERIFIED" in evaluation.reason_codes
    assert "LIQUIDITY_VERIFIED" in evaluation.reason_codes
    assert "RESERVE_NOT_VERIFIED" not in evaluation.reason_codes
    assert "RESERVE_EVIDENCE_UNAVAILABLE" not in evaluation.reason_codes

    reserve_evidence = next(
        item for item in evaluation.evidence if item["check"] == "reserve"
    )
    assert reserve_evidence["status"] == ProviderStatus.APPROVED.value
    assert reserve_evidence["provider_id"] == "mock:reserve"
    assert reserve_evidence["reference"] == "reserve-ref-1"


# ---------------------------------------------------------------------------
# 8. Reserve unavailable + fail-closed
# ---------------------------------------------------------------------------


def test_reserve_unavailable_fail_closed_denies():
    providers = _approved_providers()
    providers["reserve"] = _MockProvider(
        "reserve",
        ProviderStatus.UNAVAILABLE,
        reason="provider_request_failed",
    )

    with patch.object(config, "FAIL_CLOSED_COMPLIANCE", True):
        evaluation = evaluate_compliance(
            subject=VALID_SUBJECT,
            action="transfer",
            amount=10,
            counterparty=None,
            asset={"classification": "regulated_stablecoin"},
            providers=providers,
        )

    assert evaluation.decision == "deny"
    assert "RESERVE_PROVIDER_UNAVAILABLE" in evaluation.reason_codes
    assert "RESERVE_EVIDENCE_UNAVAILABLE" in evaluation.reason_codes
    assert "LIQUIDITY_EVIDENCE_UNAVAILABLE" in evaluation.reason_codes
    assert "RESERVE_BACKED" not in evaluation.reason_codes

    reserve_evidence = next(
        item for item in evaluation.evidence if item["check"] == "reserve"
    )
    assert reserve_evidence["status"] == ProviderStatus.UNAVAILABLE.value


# ---------------------------------------------------------------------------
# 9. Permit denial when ANY required provider check fails
#
# Parametrized across each of the three required checks to make sure the
# end-to-end /v1/permit pipeline (compliance engine -> permit bundle ->
# proof artifact) blocks the request regardless of which provider failed.
# ---------------------------------------------------------------------------


def _patch_default_providers(providers: dict[str, ComplianceProvider]):
    return patch(
        "app.services.compliance.engine._default_providers",
        return_value=providers,
    )


def test_permit_denied_when_kyc_provider_fails():
    providers = _approved_providers()
    providers["kyc"] = _MockProvider(
        "kyc",
        ProviderStatus.DENIED,
        reference="kyc-fail-1",
        reason="document_rejected",
    )

    with _patch_default_providers(providers):
        response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})

    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "deny"
    assert "KYC_DENIED" in data["reason_codes"]
    assert "KYC_NOT_VERIFIED" in data["reason_codes"]
    assert data["bundle"]["constraints"]["kyc_verified"] is False


def test_permit_denied_when_sanctions_provider_fails():
    providers = _approved_providers()
    providers["sanctions"] = _MockProvider(
        "sanctions",
        ProviderStatus.DENIED,
        reference="sanctions-fail-1",
        reason="ofac_match",
    )

    with _patch_default_providers(providers):
        response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})

    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "deny"
    assert "SANCTIONS_HIT" in data["reason_codes"]
    assert "SANCTIONS_SCREEN_DENIED" in data["reason_codes"]
    assert data["bundle"]["constraints"]["sanctions_check"] == "denied"


def test_permit_denied_when_reserve_provider_fails():
    providers = _approved_providers()
    providers["reserve"] = _MockProvider(
        "reserve",
        ProviderStatus.DENIED,
        reference="reserve-fail-1",
        reason="reserves_below_threshold",
    )

    with _patch_default_providers(providers):
        response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})

    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "deny"
    assert "RESERVE_NOT_VERIFIED" in data["reason_codes"]
    assert data["bundle"]["constraints"]["reserve_backed"] is False


# ---------------------------------------------------------------------------
# 10. Proof artifact includes evidence references, not placeholders
# ---------------------------------------------------------------------------


def test_proof_artifact_includes_real_evidence_references_not_placeholders():
    providers = _approved_providers()

    with _patch_default_providers(providers):
        response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})

    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "allow"

    # The bundle must surface the *real* provider-derived references as
    # first-class attestations, not synthetic random hashes.
    attestations = data["bundle"]["attestations"]
    assert attestations["kyc_reference"] == "kyc-ref-1"
    assert attestations["sanctions_reference"] == "sanctions-ref-1"
    assert attestations["reserve_reference"] == "reserve-ref-1"
    # Liquidity reference falls back to the overall reserve reference
    # when the provider does not split the two dimensions.
    assert attestations["liquidity_reference"] == "reserve-ref-1"
    # Legacy random_hex placeholders must be gone.
    assert "custody_hash" not in attestations
    assert "reserve_hash" not in attestations

    # The bundle's compliance_evidence list carries the structured
    # per-check evidence record produced by each mock provider, not
    # opaque booleans.
    evidence_by_check = {
        item["check"]: item for item in data["bundle"]["compliance_evidence"]
    }
    assert set(evidence_by_check.keys()) == {"kyc", "sanctions", "reserve"}
    for check, expected_ref in (
        ("kyc", "kyc-ref-1"),
        ("sanctions", "sanctions-ref-1"),
        ("reserve", "reserve-ref-1"),
    ):
        item = evidence_by_check[check]
        assert item["status"] == "approved"
        assert item["provider_id"] == f"mock:{check}"
        assert item["reference"] == expected_ref
        # No ``None`` / placeholder reference for a real approval.
        assert item["reference"]

    # Proof artifact mirrors the same evidence so downstream auditors
    # can resolve every reference without reaching back into the bundle.
    proof = data["proof_artifact"]
    proof_ctx = proof["evaluation_context"]
    assert proof_ctx["compliance_evidence"] == data["bundle"]["compliance_evidence"]
    assert proof_ctx["reserve_reference"] == "reserve-ref-1"
    assert proof_ctx["liquidity_reference"] == "reserve-ref-1"

    # The proof artifact's reason codes carry the normalized verified
    # vocabulary derived from real provider results.
    assert "KYC_VERIFIED" in proof["reason_codes"]
    assert "SANCTIONS_SCREEN_PASSED" in proof["reason_codes"]
    assert "RESERVE_VERIFIED" in proof["reason_codes"]
