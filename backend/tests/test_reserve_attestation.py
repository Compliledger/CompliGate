"""Tests for the reserve / liquidity evidence integration."""

from __future__ import annotations

import time
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.core import config
from app.main import app
from app.services.compliance import (
    ProviderResult,
    ProviderStatus,
    ReserveResult,
    ReserveStatus,
    compute_reserve_attestation_signature,
    evaluate_compliance,
    get_reserve_provider,
    validate_reserve_attestation,
)
from app.services.compliance.providers import (
    _AttestationReserveProvider,
    _HttpProvider,
    _NullProvider,
    _StaticAllowProvider,
)

client = TestClient(app)
VALID_SUBJECT = "rN7n3473SaZBCG4dFL83w7PB5XDnEHyMQX"
TRUSTED_ATTESTOR = "trusted-custodian"
SECRET = "test-secret"


# ---------------------------------------------------------------------------
# Normalized ReserveResult shape
# ---------------------------------------------------------------------------


def test_reserve_result_to_dict_has_required_fields():
    result = ReserveResult(
        provider_name="attestation:trusted-custodian",
        reserve_status=ReserveStatus.VERIFIED,
        liquidity_status=ReserveStatus.VERIFIED,
        evidence_reference="case-1",
        checked_at=1234567890,
        reason_codes=("RESERVE_EVIDENCE_VIA_ATTESTATION",),
    )
    data = result.to_dict()
    assert data["provider_name"] == "attestation:trusted-custodian"
    assert data["attestor_name"] == "attestation:trusted-custodian"
    assert data["reserve_status"] == "verified"
    assert data["liquidity_status"] == "verified"
    assert data["evidence_reference"] == "case-1"
    assert data["checked_at"] == 1234567890
    assert data["reason_codes"] == ["RESERVE_EVIDENCE_VIA_ATTESTATION"]


def test_reserve_result_provider_name_and_attestor_name_are_aliases():
    result = ReserveResult(
        provider_name="http:reserve",
        reserve_status=ReserveStatus.VERIFIED,
        liquidity_status=ReserveStatus.VERIFIED,
    )
    assert result.attestor_name == result.provider_name == "http:reserve"


# ---------------------------------------------------------------------------
# Static allow / null reserve providers surface a normalized ReserveResult
# ---------------------------------------------------------------------------


def test_null_reserve_provider_emits_unavailable_reserve_result():
    result = _NullProvider("reserve").evaluate({"subject": VALID_SUBJECT})
    assert result.status is ProviderStatus.UNAVAILABLE
    rr = result.details["reserve_result"]
    assert rr["provider_name"] == "null:reserve"
    assert rr["reserve_status"] == "unavailable"
    assert rr["liquidity_status"] == "unavailable"
    assert rr["reason_codes"] == ["RESERVE_PROVIDER_NOT_CONFIGURED"]


def test_static_allow_reserve_provider_emits_verified_reserve_result():
    result = _StaticAllowProvider("reserve").evaluate({"subject": VALID_SUBJECT})
    assert result.status is ProviderStatus.APPROVED
    rr = result.details["reserve_result"]
    assert rr["provider_name"] == "static_allow:reserve"
    assert rr["reserve_status"] == "verified"
    assert rr["liquidity_status"] == "verified"


# ---------------------------------------------------------------------------
# HTTP reserve provider — explicit reserve/liquidity statuses
# ---------------------------------------------------------------------------


def _make_http_reserve_provider(fetcher):
    return _HttpProvider(
        "reserve",
        "https://example.invalid/reserve",
        "key",
        provider_name="reserve",
        fetcher=fetcher,
    )


def test_http_reserve_provider_uses_explicit_pair_for_approval():
    def _ok(_url, _payload, _headers):
        return {
            "reserve_status": "verified",
            "liquidity_status": "verified",
            "reference": "ref-1",
        }

    provider = _make_http_reserve_provider(_ok)
    result = provider.evaluate({"subject": VALID_SUBJECT, "asset": {"currency": "RLUSD"}})
    assert result.status is ProviderStatus.APPROVED
    rr = result.details["reserve_result"]
    assert rr["reserve_status"] == "verified"
    assert rr["liquidity_status"] == "verified"
    assert rr["evidence_reference"] == "ref-1"


def test_http_reserve_provider_denies_when_either_dimension_fails():
    def _ok(_url, _payload, _headers):
        return {
            "reserve_status": "verified",
            "liquidity_status": "not_verified",
            "reference": "ref-2",
        }

    provider = _make_http_reserve_provider(_ok)
    result = provider.evaluate({"subject": VALID_SUBJECT, "asset": {"currency": "RLUSD"}})
    assert result.status is ProviderStatus.DENIED
    rr = result.details["reserve_result"]
    assert rr["reserve_status"] == "verified"
    assert rr["liquidity_status"] == "not_verified"


def test_http_reserve_provider_unavailable_when_either_dimension_unavailable():
    def _ok(_url, _payload, _headers):
        return {
            "reserve_status": "verified",
            "liquidity_status": "unavailable",
        }

    provider = _make_http_reserve_provider(_ok)
    result = provider.evaluate({"subject": VALID_SUBJECT, "asset": {"currency": "RLUSD"}})
    assert result.status is ProviderStatus.UNAVAILABLE


def test_http_reserve_provider_unknown_status_is_unavailable():
    def _ok(_url, _payload, _headers):
        return {"reserve_status": "totally-unknown", "liquidity_status": "verified"}

    provider = _make_http_reserve_provider(_ok)
    result = provider.evaluate({"subject": VALID_SUBJECT, "asset": {"currency": "RLUSD"}})
    assert result.status is ProviderStatus.UNAVAILABLE
    assert result.reason == "provider_returned_unknown_reserve_or_liquidity_status"
    rr = result.details["reserve_result"]
    assert rr["reserve_status"] == "unavailable"
    assert rr["liquidity_status"] == "unavailable"


def test_http_reserve_provider_legacy_status_field_is_supported():
    def _ok(_url, _payload, _headers):
        return {"status": "approved", "reference": "legacy-1"}

    provider = _make_http_reserve_provider(_ok)
    result = provider.evaluate({"subject": VALID_SUBJECT, "asset": {"currency": "RLUSD"}})
    assert result.status is ProviderStatus.APPROVED
    rr = result.details["reserve_result"]
    assert rr["reserve_status"] == "verified"
    assert rr["liquidity_status"] == "verified"


# ---------------------------------------------------------------------------
# Attestation ingestion path
# ---------------------------------------------------------------------------


def _signed_attestation(
    *,
    asset: str = "RLUSD",
    reserve_status: str = "verified",
    liquidity_status: str = "verified",
    attestor: str = TRUSTED_ATTESTOR,
    secret: str = SECRET,
    checked_at: int | None = None,
    evidence_reference: str = "att-1",
) -> dict:
    payload = {
        "attestor": attestor,
        "asset": asset,
        "reserve_status": reserve_status,
        "liquidity_status": liquidity_status,
        "checked_at": int(checked_at if checked_at is not None else time.time()),
        "evidence_reference": evidence_reference,
        "reason_codes": ["UPSTREAM_OK"],
    }
    payload["signature"] = compute_reserve_attestation_signature(payload, secret)
    return payload


def test_validate_reserve_attestation_accepts_signed_payload():
    attestation = _signed_attestation()
    outcome = validate_reserve_attestation(
        attestation=attestation,
        asset="RLUSD",
        trusted_attestors=(TRUSTED_ATTESTOR,),
        secret=SECRET,
    )
    assert outcome.valid is True
    assert outcome.result.reserve_status is ReserveStatus.VERIFIED
    assert outcome.result.liquidity_status is ReserveStatus.VERIFIED
    assert outcome.result.provider_name == f"attestation:{TRUSTED_ATTESTOR}"
    assert "RESERVE_EVIDENCE_VIA_ATTESTATION" in outcome.result.reason_codes


def test_validate_reserve_attestation_rejects_untrusted_attestor():
    attestation = _signed_attestation(attestor="rogue-attestor")
    outcome = validate_reserve_attestation(
        attestation=attestation,
        asset="RLUSD",
        trusted_attestors=(TRUSTED_ATTESTOR,),
        secret=SECRET,
    )
    assert outcome.valid is False
    assert outcome.error == "RESERVE_ATTESTATION_UNTRUSTED_ATTESTOR"
    assert outcome.result.reserve_status is ReserveStatus.UNAVAILABLE


def test_validate_reserve_attestation_rejects_bad_signature():
    attestation = _signed_attestation()
    attestation["signature"] = "deadbeef"
    outcome = validate_reserve_attestation(
        attestation=attestation,
        asset="RLUSD",
        trusted_attestors=(TRUSTED_ATTESTOR,),
        secret=SECRET,
    )
    assert outcome.valid is False
    assert outcome.error == "RESERVE_ATTESTATION_SIGNATURE_INVALID"


def test_validate_reserve_attestation_rejects_asset_mismatch():
    attestation = _signed_attestation(asset="USDC")
    outcome = validate_reserve_attestation(
        attestation=attestation,
        asset="RLUSD",
        trusted_attestors=(TRUSTED_ATTESTOR,),
        secret=SECRET,
    )
    assert outcome.valid is False
    assert outcome.error == "RESERVE_ATTESTATION_ASSET_MISMATCH"


def test_validate_reserve_attestation_rejects_expired_payload():
    attestation = _signed_attestation(checked_at=int(time.time()) - 48 * 3600)
    outcome = validate_reserve_attestation(
        attestation=attestation,
        asset="RLUSD",
        trusted_attestors=(TRUSTED_ATTESTOR,),
        secret=SECRET,
    )
    assert outcome.valid is False
    assert outcome.error == "RESERVE_ATTESTATION_EXPIRED"


def test_validate_reserve_attestation_missing_returns_unavailable():
    outcome = validate_reserve_attestation(
        attestation=None,
        asset="RLUSD",
        trusted_attestors=(TRUSTED_ATTESTOR,),
        secret=SECRET,
    )
    assert outcome.valid is False
    assert outcome.error == "RESERVE_ATTESTATION_MISSING"


# ---------------------------------------------------------------------------
# AttestationReserveProvider end-to-end
# ---------------------------------------------------------------------------


def test_attestation_reserve_provider_approves_with_valid_attestation():
    provider = _AttestationReserveProvider(
        secret=SECRET, trusted_attestors=(TRUSTED_ATTESTOR,)
    )
    result = provider.evaluate(
        {
            "subject": VALID_SUBJECT,
            "asset": {"currency": "RLUSD"},
            "reserve_attestation": _signed_attestation(),
        }
    )
    assert result.status is ProviderStatus.APPROVED
    assert result.reason == "RESERVE_VERIFIED_VIA_ATTESTATION"
    rr = result.details["reserve_result"]
    assert rr["provider_name"] == f"attestation:{TRUSTED_ATTESTOR}"
    assert rr["reserve_status"] == "verified"
    assert rr["liquidity_status"] == "verified"


def test_attestation_reserve_provider_denies_when_attestation_says_not_verified():
    provider = _AttestationReserveProvider(
        secret=SECRET, trusted_attestors=(TRUSTED_ATTESTOR,)
    )
    result = provider.evaluate(
        {
            "subject": VALID_SUBJECT,
            "asset": {"currency": "RLUSD"},
            "reserve_attestation": _signed_attestation(reserve_status="not_verified"),
        }
    )
    assert result.status is ProviderStatus.DENIED
    assert result.reason == "RESERVE_NOT_VERIFIED_VIA_ATTESTATION"


def test_attestation_reserve_provider_unavailable_when_attestation_missing():
    provider = _AttestationReserveProvider(
        secret=SECRET, trusted_attestors=(TRUSTED_ATTESTOR,)
    )
    result = provider.evaluate(
        {"subject": VALID_SUBJECT, "asset": {"currency": "RLUSD"}}
    )
    assert result.status is ProviderStatus.UNAVAILABLE
    assert result.reason == "RESERVE_ATTESTATION_MISSING"
    rr = result.details["reserve_result"]
    assert rr["reserve_status"] == "unavailable"
    assert rr["liquidity_status"] == "unavailable"


# ---------------------------------------------------------------------------
# Provider factory wiring
# ---------------------------------------------------------------------------


def test_reserve_provider_factory_builds_attestation_provider_when_configured():
    with patch.object(config, "RESERVE_PROVIDER", "attestation"):
        provider = get_reserve_provider()
    assert isinstance(provider, _AttestationReserveProvider)


def test_attestation_kind_only_allowed_for_reserve():
    with patch.object(config, "KYC_PROVIDER", "attestation"):
        from app.services.compliance.providers import get_kyc_provider

        provider = get_kyc_provider()
    assert isinstance(provider, _NullProvider)


# ---------------------------------------------------------------------------
# Engine: normalized reason codes + fail-closed semantics
# ---------------------------------------------------------------------------


def test_engine_emits_normalized_reserve_reason_codes_on_approval():
    evaluation = evaluate_compliance(
        subject=VALID_SUBJECT,
        action="transfer",
        amount=10,
        counterparty=None,
        providers={
            "kyc": _StaticAllowProvider("kyc"),
            "sanctions": _StaticAllowProvider("sanctions"),
            "reserve": _StaticAllowProvider("reserve"),
        },
    )
    assert "RESERVE_STATUS_VERIFIED" in evaluation.reason_codes
    assert "LIQUIDITY_STATUS_VERIFIED" in evaluation.reason_codes


def test_engine_emits_normalized_reserve_reason_codes_when_unavailable():
    with patch.object(config, "RESERVE_PROVIDER", "null"), patch.object(
        config, "FAIL_CLOSED_COMPLIANCE", True
    ):
        evaluation = evaluate_compliance(
            subject=VALID_SUBJECT,
            action="transfer",
            amount=10,
            counterparty=None,
        )
    assert "RESERVE_STATUS_UNAVAILABLE" in evaluation.reason_codes
    assert "LIQUIDITY_STATUS_UNAVAILABLE" in evaluation.reason_codes
    assert evaluation.decision == "deny"


def test_engine_emits_split_reserve_codes_when_only_liquidity_fails():
    class _ReservePartial(_StaticAllowProvider):
        def evaluate(self, context):  # noqa: ARG002
            rr = ReserveResult(
                provider_name="test:partial",
                reserve_status=ReserveStatus.VERIFIED,
                liquidity_status=ReserveStatus.NOT_VERIFIED,
                evidence_reference="ref-x",
                reason_codes=("LIQUIDITY_INSUFFICIENT",),
            )
            return ProviderResult(
                check="reserve",
                status=ProviderStatus.DENIED,
                provider_id="test:partial",
                reference="ref-x",
                details={"reserve_result": rr.to_dict()},
            )

    evaluation = evaluate_compliance(
        subject=VALID_SUBJECT,
        action="transfer",
        amount=10,
        counterparty=None,
        providers={
            "kyc": _StaticAllowProvider("kyc"),
            "sanctions": _StaticAllowProvider("sanctions"),
            "reserve": _ReservePartial("reserve"),
        },
    )
    assert evaluation.decision == "deny"
    assert "RESERVE_STATUS_VERIFIED" in evaluation.reason_codes
    assert "LIQUIDITY_STATUS_NOT_VERIFIED" in evaluation.reason_codes


# ---------------------------------------------------------------------------
# End-to-end: /v1/permit fails closed when reserve provider unavailable
# ---------------------------------------------------------------------------


def test_permit_endpoint_fails_closed_when_reserve_provider_unavailable():
    with patch.object(config, "RESERVE_PROVIDER", "null"):
        response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})

    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "deny"
    assert "RESERVE_PROVIDER_UNAVAILABLE" in data["reason_codes"]
    assert "RESERVE_STATUS_UNAVAILABLE" in data["reason_codes"]
    assert "LIQUIDITY_STATUS_UNAVAILABLE" in data["reason_codes"]
    # The bundle must not claim reserve / liquidity were verified when no
    # reserve evidence was reachable.
    assert data["bundle"]["constraints"]["reserve_backed"] is False
    assert data["bundle"]["constraints"]["liquidity_verified"] is False
    # The normalized ReserveResult is surfaced as a first-class
    # attestation so downstream consumers do not have to walk the
    # evidence list to find it.
    rr = data["bundle"]["attestations"]["reserve_result"]
    assert rr["reserve_status"] == "unavailable"
    assert rr["liquidity_status"] == "unavailable"


def test_permit_endpoint_emits_reserve_result_attestation_on_success():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "allow"
    rr = data["bundle"]["attestations"]["reserve_result"]
    assert rr["reserve_status"] == "verified"
    assert rr["liquidity_status"] == "verified"
    assert rr["provider_name"] == "static_allow:reserve"


def test_permit_endpoint_accepts_reserve_attestation_payload():
    attestation = _signed_attestation(asset="RLUSD")
    with patch.object(config, "RESERVE_PROVIDER", "attestation"), patch.object(
        config, "RESERVE_ATTESTATION_SECRET", SECRET
    ), patch.object(
        config, "RESERVE_ATTESTATION_TRUSTED_ATTESTORS", [TRUSTED_ATTESTOR]
    ):
        response = client.post(
            "/v1/permit",
            json={
                "subject": VALID_SUBJECT,
                "reserve_attestation": attestation,
            },
        )
    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "allow"
    assert data["bundle"]["constraints"]["reserve_backed"] is True
    assert data["bundle"]["constraints"]["liquidity_verified"] is True
    rr = data["bundle"]["attestations"]["reserve_result"]
    assert rr["provider_name"] == f"attestation:{TRUSTED_ATTESTOR}"
    assert rr["reserve_status"] == "verified"
    assert rr["liquidity_status"] == "verified"


def test_permit_endpoint_denies_when_reserve_attestation_missing():
    with patch.object(config, "RESERVE_PROVIDER", "attestation"), patch.object(
        config, "RESERVE_ATTESTATION_SECRET", SECRET
    ), patch.object(
        config, "RESERVE_ATTESTATION_TRUSTED_ATTESTORS", [TRUSTED_ATTESTOR]
    ):
        response = client.post(
            "/v1/permit",
            json={"subject": VALID_SUBJECT},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "deny"
    assert "RESERVE_PROVIDER_UNAVAILABLE" in data["reason_codes"]
    assert data["bundle"]["constraints"]["reserve_backed"] is False
    assert data["bundle"]["constraints"]["liquidity_verified"] is False
