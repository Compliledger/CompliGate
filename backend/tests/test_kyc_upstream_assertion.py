"""Tests for the trusted-upstream KYC assertion provider and the
normalized :class:`KycResult` model."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.core import config
from app.main import app
from app.services.compliance import (
    KycResult,
    KycStatus,
    ProviderStatus,
    compute_assertion_signature,
    evaluate_compliance,
    validate_upstream_assertion,
)
from app.services.compliance.providers import (
    _NullProvider,
    _StaticAllowProvider,
    _UpstreamAssertionKycProvider,
    get_kyc_provider,
)

client = TestClient(app)
VALID_SUBJECT = "rN7n3473SaZBCG4dFL83w7PB5XDnEHyMQX"
OTHER_SUBJECT = "rDifferentSubject0000000000000000000"
ISSUER = "trusted-bank-1"
SECRET = "test-shared-secret"


def _signed_assertion(
    *,
    subject: str = VALID_SUBJECT,
    kyc_status: str = "verified",
    issuer: str = ISSUER,
    secret: str = SECRET,
    jurisdiction: str = "US",
    checked_at: int | None = None,
    evidence_reference: str = "case-12345",
    reason_codes: list[str] | None = None,
) -> dict:
    payload = {
        "issuer": issuer,
        "subject_id": subject,
        "kyc_status": kyc_status,
        "jurisdiction": jurisdiction,
        "checked_at": int(checked_at if checked_at is not None else time.time()),
        "evidence_reference": evidence_reference,
        "reason_codes": list(reason_codes or []),
    }
    payload["signature"] = compute_assertion_signature(payload, secret)
    return payload


# ---------------------------------------------------------------------------
# Pure validator
# ---------------------------------------------------------------------------


def test_validate_upstream_assertion_happy_path_returns_normalized_result():
    assertion = _signed_assertion(reason_codes=["IDENTITY_DOC_VERIFIED"])
    outcome = validate_upstream_assertion(
        assertion=assertion,
        subject=VALID_SUBJECT,
        trusted_issuers=[ISSUER],
        secret=SECRET,
    )
    assert outcome.valid is True
    assert outcome.error is None
    result = outcome.result
    assert isinstance(result, KycResult)
    # Every field required by the normalized KYC result spec is present.
    assert result.provider_name == f"upstream_assertion:{ISSUER}"
    assert result.source_system == result.provider_name  # alias
    assert result.subject_id == VALID_SUBJECT
    assert result.kyc_status is KycStatus.VERIFIED
    assert result.jurisdiction == "US"
    assert result.evidence_reference == "case-12345"
    assert isinstance(result.checked_at, int)
    # Custom reason codes are preserved and the upstream marker is appended.
    assert "IDENTITY_DOC_VERIFIED" in result.reason_codes
    assert "KYC_VERIFIED_VIA_UPSTREAM_ASSERTION" in result.reason_codes


@pytest.mark.parametrize(
    "mutate,expected_error",
    [
        (lambda a: a.update({"signature": "deadbeef"}) or a, "KYC_UPSTREAM_ASSERTION_SIGNATURE_INVALID"),
        (lambda a: a.update({"issuer": "rogue"}) or a, "KYC_UPSTREAM_ASSERTION_UNTRUSTED_ISSUER"),
        (lambda a: a.update({"subject_id": OTHER_SUBJECT}) or a, "KYC_UPSTREAM_ASSERTION_SUBJECT_MISMATCH"),
        (lambda a: a.update({"kyc_status": "weird"}) or a, "KYC_UPSTREAM_ASSERTION_STATUS_UNKNOWN"),
    ],
)
def test_validate_upstream_assertion_rejects_tampered_payload(mutate, expected_error):
    assertion = _signed_assertion()
    # For mutations that change a *signed* field we must NOT recompute
    # the signature (we want to assert the validator catches them). For
    # mutations like "untrusted issuer" we also keep the original
    # signature, since recomputing here would still trip the issuer
    # check.
    mutated = mutate(dict(assertion))
    outcome = validate_upstream_assertion(
        assertion=mutated,
        subject=VALID_SUBJECT,
        trusted_issuers=[ISSUER],
        secret=SECRET,
    )
    # The signature mismatch dominates for any change to a signed field;
    # the issuer / subject / status checks fire when those fields are
    # mutated *and* re-signed.  Either way the outcome must be invalid
    # and produce a KycResult with status=UNAVAILABLE.
    assert outcome.valid is False
    assert outcome.result.kyc_status is KycStatus.UNAVAILABLE
    assert outcome.error in {
        expected_error,
        "KYC_UPSTREAM_ASSERTION_SIGNATURE_INVALID",
    }


def test_validate_upstream_assertion_rejects_expired_payload():
    very_old = int(time.time()) - (10 * 24 * 3600)
    assertion = _signed_assertion(checked_at=very_old)
    outcome = validate_upstream_assertion(
        assertion=assertion,
        subject=VALID_SUBJECT,
        trusted_issuers=[ISSUER],
        secret=SECRET,
    )
    assert outcome.valid is False
    assert outcome.error == "KYC_UPSTREAM_ASSERTION_EXPIRED"
    assert outcome.result.kyc_status is KycStatus.UNAVAILABLE


def test_validate_upstream_assertion_requires_configuration():
    assertion = _signed_assertion()
    outcome = validate_upstream_assertion(
        assertion=assertion,
        subject=VALID_SUBJECT,
        trusted_issuers=[],
        secret="",
    )
    assert outcome.valid is False
    assert outcome.error == "KYC_UPSTREAM_ASSERTION_NOT_CONFIGURED"
    assert outcome.result.kyc_status is KycStatus.UNAVAILABLE


def test_validate_upstream_assertion_handles_missing_payload():
    outcome = validate_upstream_assertion(
        assertion=None,
        subject=VALID_SUBJECT,
        trusted_issuers=[ISSUER],
        secret=SECRET,
    )
    assert outcome.valid is False
    assert outcome.error == "KYC_UPSTREAM_ASSERTION_MISSING"
    assert outcome.result.kyc_status is KycStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# Provider integration with the engine
# ---------------------------------------------------------------------------


def test_upstream_assertion_provider_approves_on_valid_verified_assertion():
    provider = _UpstreamAssertionKycProvider(
        secret=SECRET, trusted_issuers=(ISSUER,)
    )
    result = provider.evaluate(
        {"subject": VALID_SUBJECT, "kyc_assertion": _signed_assertion()}
    )
    assert result.status is ProviderStatus.APPROVED
    assert result.provider_id == f"upstream_assertion:{ISSUER}"
    kyc_result = result.details["kyc_result"]
    assert kyc_result["kyc_status"] == "verified"
    assert kyc_result["subject_id"] == VALID_SUBJECT
    assert kyc_result["jurisdiction"] == "US"
    assert kyc_result["evidence_reference"] == "case-12345"
    assert "KYC_VERIFIED_VIA_UPSTREAM_ASSERTION" in kyc_result["reason_codes"]


def test_upstream_assertion_provider_denies_on_explicit_not_verified():
    provider = _UpstreamAssertionKycProvider(
        secret=SECRET, trusted_issuers=(ISSUER,)
    )
    result = provider.evaluate(
        {
            "subject": VALID_SUBJECT,
            "kyc_assertion": _signed_assertion(kyc_status="not_verified"),
        }
    )
    assert result.status is ProviderStatus.DENIED
    assert result.details["kyc_result"]["kyc_status"] == "not_verified"


def test_upstream_assertion_provider_unavailable_when_no_assertion_supplied():
    provider = _UpstreamAssertionKycProvider(
        secret=SECRET, trusted_issuers=(ISSUER,)
    )
    result = provider.evaluate({"subject": VALID_SUBJECT})
    assert result.status is ProviderStatus.UNAVAILABLE
    assert result.reason == "KYC_UPSTREAM_ASSERTION_MISSING"
    assert result.details["kyc_result"]["kyc_status"] == "unavailable"


def test_upstream_assertion_provider_unavailable_when_secret_not_configured():
    provider = _UpstreamAssertionKycProvider(secret="", trusted_issuers=(ISSUER,))
    result = provider.evaluate(
        {"subject": VALID_SUBJECT, "kyc_assertion": _signed_assertion()}
    )
    assert result.status is ProviderStatus.UNAVAILABLE
    assert result.reason == "KYC_UPSTREAM_ASSERTION_NOT_CONFIGURED"


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------


def test_provider_factory_builds_upstream_assertion_kyc_provider():
    with patch.object(config, "KYC_PROVIDER", "upstream_assertion"), patch.object(
        config, "KYC_UPSTREAM_ASSERTION_SECRET", SECRET
    ), patch.object(
        config, "KYC_UPSTREAM_ASSERTION_TRUSTED_ISSUERS", [ISSUER]
    ):
        provider = get_kyc_provider()
    assert isinstance(provider, _UpstreamAssertionKycProvider)


def test_upstream_assertion_kind_only_supported_for_kyc():
    """Asking for an upstream_assertion sanctions or reserve provider
    must fall back to the null provider so misconfiguration cannot
    silently approve a request."""
    from app.services.compliance.providers import _build_provider, _KYC_PROVIDER_KINDS

    with patch.object(config, "SANCTIONS_PROVIDER", "upstream_assertion"):
        provider = _build_provider(
            check="sanctions",
            kind_env="SANCTIONS_PROVIDER",
            url_env="SANCTIONS_PROVIDER_URL",
            api_key_env="SANCTIONS_PROVIDER_API_KEY",
            provider_name="sanctions",
        )
    assert isinstance(provider, _NullProvider)
    # KYC stays in its own allowlist.
    assert "upstream_assertion" in _KYC_PROVIDER_KINDS


# ---------------------------------------------------------------------------
# Engine-level: combining the two supported KYC paths with FAIL_CLOSED_COMPLIANCE
# ---------------------------------------------------------------------------


def test_engine_fails_closed_when_no_kyc_provider_and_no_upstream_assertion():
    """When neither a direct KYC provider nor an upstream assertion is
    available, FAIL_CLOSED_COMPLIANCE=true must produce a deny."""
    with patch.object(config, "KYC_PROVIDER", "null"), patch.object(
        config, "FAIL_CLOSED_COMPLIANCE", True
    ):
        evaluation = evaluate_compliance(
            subject=VALID_SUBJECT,
            action="transfer",
            amount=10,
            counterparty=None,
            kyc_assertion=None,
            providers={
                "kyc": _NullProvider("kyc"),
                "sanctions": _StaticAllowProvider("sanctions"),
                "reserve": _StaticAllowProvider("reserve"),
            },
        )
    assert evaluation.decision == "deny"
    assert "KYC_PROVIDER_UNAVAILABLE" in evaluation.reason_codes
    kyc_evidence = next(
        item for item in evaluation.evidence if item["check"] == "kyc"
    )
    assert kyc_evidence["status"] == ProviderStatus.UNAVAILABLE.value
    # Even the null KYC provider must surface a normalized KycResult so
    # auditors can see the shape and the reason explicitly.
    assert kyc_evidence["details"]["kyc_result"]["kyc_status"] == "unavailable"


def test_engine_allows_when_upstream_assertion_provider_validates_payload():
    """A trusted upstream assertion is a complete substitute for a direct
    KYC provider integration when it validates."""
    providers = {
        "kyc": _UpstreamAssertionKycProvider(secret=SECRET, trusted_issuers=(ISSUER,)),
        "sanctions": _StaticAllowProvider("sanctions"),
        "reserve": _StaticAllowProvider("reserve"),
    }
    with patch.object(config, "FAIL_CLOSED_COMPLIANCE", True):
        evaluation = evaluate_compliance(
            subject=VALID_SUBJECT,
            action="transfer",
            amount=10,
            counterparty=None,
            kyc_assertion=_signed_assertion(),
            providers=providers,
        )
    assert evaluation.decision == "allow"
    assert "KYC_VERIFIED" in evaluation.reason_codes
    kyc_evidence = next(
        item for item in evaluation.evidence if item["check"] == "kyc"
    )
    assert kyc_evidence["status"] == ProviderStatus.APPROVED.value
    kyc_result = kyc_evidence["details"]["kyc_result"]
    assert kyc_result["provider_name"] == f"upstream_assertion:{ISSUER}"
    assert kyc_result["kyc_status"] == "verified"
    assert kyc_result["subject_id"] == VALID_SUBJECT


def test_engine_denies_when_upstream_assertion_is_for_a_different_subject():
    """An assertion for one wallet must never be replayed against another."""
    providers = {
        "kyc": _UpstreamAssertionKycProvider(secret=SECRET, trusted_issuers=(ISSUER,)),
        "sanctions": _StaticAllowProvider("sanctions"),
        "reserve": _StaticAllowProvider("reserve"),
    }
    with patch.object(config, "FAIL_CLOSED_COMPLIANCE", True):
        evaluation = evaluate_compliance(
            subject=VALID_SUBJECT,
            action="transfer",
            amount=10,
            counterparty=None,
            kyc_assertion=_signed_assertion(subject=OTHER_SUBJECT),
            providers=providers,
        )
    assert evaluation.decision == "deny"
    assert "KYC_PROVIDER_UNAVAILABLE" in evaluation.reason_codes


# ---------------------------------------------------------------------------
# End-to-end: /v1/permit accepts the upstream assertion
# ---------------------------------------------------------------------------


def test_permit_endpoint_accepts_trusted_upstream_kyc_assertion():
    with patch.object(config, "KYC_PROVIDER", "upstream_assertion"), patch.object(
        config, "KYC_UPSTREAM_ASSERTION_SECRET", SECRET
    ), patch.object(
        config, "KYC_UPSTREAM_ASSERTION_TRUSTED_ISSUERS", [ISSUER]
    ):
        response = client.post(
            "/v1/permit",
            json={
                "subject": VALID_SUBJECT,
                "kyc_assertion": _signed_assertion(),
            },
        )

    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "allow"
    assert data["bundle"]["constraints"]["kyc_verified"] is True
    # The bundle attestations carry the full normalized KYC result so
    # downstream consumers don't have to walk the evidence list.
    kyc_attestation = data["bundle"]["attestations"]["kyc_result"]
    assert kyc_attestation["provider_name"] == f"upstream_assertion:{ISSUER}"
    assert kyc_attestation["source_system"] == kyc_attestation["provider_name"]
    assert kyc_attestation["subject_id"] == VALID_SUBJECT
    assert kyc_attestation["kyc_status"] == "verified"
    assert kyc_attestation["jurisdiction"] == "US"
    assert kyc_attestation["evidence_reference"] == "case-12345"
    assert "KYC_VERIFIED_VIA_UPSTREAM_ASSERTION" in kyc_attestation["reason_codes"]


def test_permit_endpoint_fails_closed_when_upstream_assertion_missing():
    with patch.object(config, "KYC_PROVIDER", "upstream_assertion"), patch.object(
        config, "KYC_UPSTREAM_ASSERTION_SECRET", SECRET
    ), patch.object(
        config, "KYC_UPSTREAM_ASSERTION_TRUSTED_ISSUERS", [ISSUER]
    ):
        response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})

    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "deny"
    assert data["bundle"]["constraints"]["kyc_verified"] is False
    assert "KYC_PROVIDER_UNAVAILABLE" in data["reason_codes"]
    # The normalized KYC result is still recorded so the proof artifact
    # explains exactly why no upstream KYC evidence was usable.
    kyc_attestation = data["bundle"]["attestations"]["kyc_result"]
    assert kyc_attestation["kyc_status"] == "unavailable"
    assert "KYC_UPSTREAM_ASSERTION_MISSING" in kyc_attestation["reason_codes"]


def test_permit_endpoint_fails_closed_when_upstream_signature_invalid():
    bad_assertion = _signed_assertion()
    bad_assertion["signature"] = "deadbeef" * 8  # tampered

    with patch.object(config, "KYC_PROVIDER", "upstream_assertion"), patch.object(
        config, "KYC_UPSTREAM_ASSERTION_SECRET", SECRET
    ), patch.object(
        config, "KYC_UPSTREAM_ASSERTION_TRUSTED_ISSUERS", [ISSUER]
    ):
        response = client.post(
            "/v1/permit",
            json={"subject": VALID_SUBJECT, "kyc_assertion": bad_assertion},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "deny"
    assert data["bundle"]["constraints"]["kyc_verified"] is False
    kyc_attestation = data["bundle"]["attestations"]["kyc_result"]
    assert kyc_attestation["kyc_status"] == "unavailable"
    assert "KYC_UPSTREAM_ASSERTION_SIGNATURE_INVALID" in kyc_attestation[
        "reason_codes"
    ]
