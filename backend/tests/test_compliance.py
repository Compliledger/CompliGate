from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from app.core import config
from app.main import app
from app.services.compliance import (
    ProviderResult,
    ProviderStatus,
    evaluate_compliance,
)
from app.services.compliance.providers import (
    _HttpProvider,
    _NullProvider,
    _StaticAllowProvider,
    get_kyc_provider,
    get_reserve_provider,
    get_sanctions_provider,
)

client = TestClient(app)
VALID_SUBJECT = "rN7n3473SaZBCG4dFL83w7PB5XDnEHyMQX"


# ---------------------------------------------------------------------------
# Engine-level: fail-closed when no provider is configured
# ---------------------------------------------------------------------------


def test_engine_fails_closed_when_providers_default_to_null():
    with patch.object(config, "KYC_PROVIDER", "null"), patch.object(
        config, "SANCTIONS_PROVIDER", "null"
    ), patch.object(config, "RESERVE_PROVIDER", "null"), patch.object(
        config, "FAIL_CLOSED_COMPLIANCE", True
    ):
        evaluation = evaluate_compliance(
            subject=VALID_SUBJECT,
            action="transfer",
            amount=10,
            counterparty=None,
        )

    assert evaluation.decision == "deny"
    assert "KYC_PROVIDER_UNAVAILABLE" in evaluation.reason_codes
    assert "SANCTIONS_PROVIDER_UNAVAILABLE" in evaluation.reason_codes
    assert "RESERVE_PROVIDER_UNAVAILABLE" in evaluation.reason_codes
    # Evidence must be persisted for every check, even when the providers
    # are unavailable, so the proof artifact is fully traceable.
    assert {item["check"] for item in evaluation.evidence} == {"kyc", "sanctions", "reserve"}
    for item in evaluation.evidence:
        assert item["status"] == ProviderStatus.UNAVAILABLE.value
        assert item["provider_id"].startswith("null:")


def test_engine_denies_on_missing_provider_when_fail_closed_enabled():
    """When FAIL_CLOSED_COMPLIANCE=true (default), a missing provider must
    deny rather than silently pass."""
    with patch.object(config, "FAIL_CLOSED_COMPLIANCE", True):
        evaluation = evaluate_compliance(
            subject=VALID_SUBJECT,
            action="transfer",
            amount=10,
            counterparty=None,
            providers={
                "kyc": _StaticAllowProvider("kyc"),
                "sanctions": _StaticAllowProvider("sanctions"),
                # reserve provider intentionally missing
            },
        )
    assert evaluation.decision == "deny"
    assert "RESERVE_PROVIDER_UNAVAILABLE" in evaluation.reason_codes
    reserve_evidence = next(item for item in evaluation.evidence if item["check"] == "reserve")
    assert reserve_evidence["status"] == ProviderStatus.UNAVAILABLE.value
    assert reserve_evidence["details"]["fail_closed"] is True


def test_engine_allows_on_missing_provider_when_fail_closed_disabled():
    """With FAIL_CLOSED_COMPLIANCE explicitly disabled, missing providers
    are recorded as skipped instead of blocking the decision."""
    with patch.object(config, "FAIL_CLOSED_COMPLIANCE", False):
        evaluation = evaluate_compliance(
            subject=VALID_SUBJECT,
            action="transfer",
            amount=10,
            counterparty=None,
            providers={
                "kyc": _StaticAllowProvider("kyc"),
                "sanctions": _StaticAllowProvider("sanctions"),
                # reserve provider intentionally missing
            },
        )
    assert evaluation.decision == "allow"
    assert "RESERVE_CHECK_SKIPPED" in evaluation.reason_codes
    assert "RESERVE_PROVIDER_UNAVAILABLE" not in evaluation.reason_codes
    reserve_evidence = next(item for item in evaluation.evidence if item["check"] == "reserve")
    assert reserve_evidence["details"]["fail_closed"] is False


def test_engine_static_allow_produces_traceable_evidence():
    with patch.object(config, "KYC_PROVIDER", "static_allow"), patch.object(
        config, "SANCTIONS_PROVIDER", "static_allow"
    ), patch.object(config, "RESERVE_PROVIDER", "static_allow"):
        evaluation = evaluate_compliance(
            subject=VALID_SUBJECT,
            action="transfer",
            amount=10,
            counterparty=None,
        )

    assert evaluation.decision == "allow"
    assert "KYC_VERIFIED" in evaluation.reason_codes
    assert "SANCTIONS_PASSED" in evaluation.reason_codes
    assert "RESERVE_BACKED" in evaluation.reason_codes
    for item in evaluation.evidence:
        assert item["provider_id"].startswith("static_allow:")
        assert item["status"] == ProviderStatus.APPROVED.value


def test_engine_denies_when_any_provider_returns_denied():
    class _DenyKyc(_StaticAllowProvider):
        def evaluate(self, context):
            return ProviderResult(
                check="kyc",
                status=ProviderStatus.DENIED,
                provider_id="test:deny",
                reason="sanctioned_entity",
            )

    providers = {
        "kyc": _DenyKyc("kyc"),
        "sanctions": _StaticAllowProvider("sanctions"),
        "reserve": _StaticAllowProvider("reserve"),
    }
    evaluation = evaluate_compliance(
        subject=VALID_SUBJECT,
        action="transfer",
        amount=10,
        counterparty=None,
        providers=providers,
    )
    assert evaluation.decision == "deny"
    assert "KYC_DENIED" in evaluation.reason_codes
    # Evidence still includes the explicit denial reason.
    kyc_evidence = next(item for item in evaluation.evidence if item["check"] == "kyc")
    assert kyc_evidence["status"] == ProviderStatus.DENIED.value
    assert kyc_evidence["reason"] == "sanctioned_entity"


# ---------------------------------------------------------------------------
# HTTP provider: transport failures must yield an "unavailable" result
# (fail-closed) rather than raising.
# ---------------------------------------------------------------------------


def test_http_provider_returns_unavailable_on_transport_error():
    def _fail(_url, _payload, _headers):
        raise RuntimeError("boom")

    provider = _HttpProvider(
        "kyc",
        "https://example.invalid/check",
        "key",
        provider_name="kyc",
        fetcher=_fail,
    )
    result = provider.evaluate({"subject": VALID_SUBJECT})
    assert result.status is ProviderStatus.UNAVAILABLE
    assert result.reason == "provider_request_failed"
    assert result.provider_id == "http:kyc"


def test_http_provider_uses_response_status_and_reference():
    def _ok(_url, _payload, _headers):
        return {"status": "approved", "reference": "ref-123", "details": {"score": 99}}

    provider = _HttpProvider(
        "kyc",
        "https://example.invalid/check",
        "key",
        provider_name="kyc",
        fetcher=_ok,
    )
    result = provider.evaluate({"subject": VALID_SUBJECT})
    assert result.status is ProviderStatus.APPROVED
    assert result.reference == "ref-123"
    # The base details from the upstream response are preserved...
    assert result.details["score"] == 99
    # ...and a normalized KYC result is attached for KYC checks so the
    # bundle / proof artifact always carries the required fields.
    kyc_result = result.details["kyc_result"]
    assert kyc_result["provider_name"] == "http:kyc"
    assert kyc_result["source_system"] == "http:kyc"
    assert kyc_result["subject_id"] == VALID_SUBJECT
    assert kyc_result["kyc_status"] == "verified"
    assert kyc_result["evidence_reference"] == "ref-123"
    assert "jurisdiction" in kyc_result
    assert "checked_at" in kyc_result
    assert "reason_codes" in kyc_result


def test_http_provider_unknown_status_is_unavailable():
    def _bad(_url, _payload, _headers):
        return {"status": "maybe"}

    provider = _HttpProvider(
        "sanctions",
        "https://example.invalid/check",
        "",
        provider_name="sanctions",
        fetcher=_bad,
    )
    result = provider.evaluate({"subject": VALID_SUBJECT})
    assert result.status is ProviderStatus.UNAVAILABLE
    assert result.reason == "provider_returned_unknown_status"


def test_http_provider_missing_url_is_unavailable():
    provider = _HttpProvider("kyc", "", "", provider_name="kyc", fetcher=lambda *a, **k: {})
    result = provider.evaluate({"subject": VALID_SUBJECT})
    assert result.status is ProviderStatus.UNAVAILABLE
    assert result.reason == "provider_url_missing"


# ---------------------------------------------------------------------------
# Provider factory wiring
# ---------------------------------------------------------------------------


def test_provider_factory_defaults_to_null_when_not_configured():
    with patch.object(config, "KYC_PROVIDER", ""), patch.object(
        config, "SANCTIONS_PROVIDER", ""
    ), patch.object(config, "RESERVE_PROVIDER", ""):
        assert isinstance(get_kyc_provider(), _NullProvider)
        assert isinstance(get_sanctions_provider(), _NullProvider)
        assert isinstance(get_reserve_provider(), _NullProvider)


def test_provider_factory_unknown_kind_falls_back_to_null():
    with patch.object(config, "KYC_PROVIDER", "definitely-not-supported"):
        assert isinstance(get_kyc_provider(), _NullProvider)


def test_provider_factory_builds_http_provider_when_configured():
    with patch.object(config, "KYC_PROVIDER", "http"), patch.object(
        config, "KYC_PROVIDER_URL", "https://example.invalid/kyc"
    ), patch.object(config, "KYC_PROVIDER_API_KEY", "secret"):
        provider = get_kyc_provider()
    assert isinstance(provider, _HttpProvider)


# ---------------------------------------------------------------------------
# End-to-end: /v1/permit reflects the real provider decision
# ---------------------------------------------------------------------------


def test_permit_endpoint_emits_provider_evidence_in_proof_artifact():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()

    # decision_result reflects the configured providers (static_allow in tests).
    assert data["decision_result"] == "allow"

    # The bundle must record the structured per-check evidence used to
    # derive the decision, not synthetic random hashes.
    assert "compliance_evidence" in data["bundle"]
    checks = {item["check"]: item for item in data["bundle"]["compliance_evidence"]}
    assert set(checks.keys()) == {"kyc", "sanctions", "reserve"}
    for item in checks.values():
        assert item["provider_id"].startswith("static_allow:")
        assert item["status"] == "approved"

    # Old random_hex placeholder attestations must be gone.
    attestations = data["bundle"]["attestations"]
    assert "custody_hash" not in attestations
    assert "reserve_hash" not in attestations
    # Reserve attestation is now the provider reference.
    assert attestations["reserve_reference"] == checks["reserve"]["reference"]
    assert attestations["kyc_reference"] == checks["kyc"]["reference"]

    # Proof artifact must carry the same evidence for downstream auditors.
    proof_ctx = data["proof_artifact"]["evaluation_context"]
    assert proof_ctx["compliance_evidence"] == data["bundle"]["compliance_evidence"]


def test_permit_endpoint_fails_closed_when_kyc_provider_unavailable():
    with patch.object(config, "KYC_PROVIDER", "null"):
        response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})

    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "deny"
    assert "KYC_PROVIDER_UNAVAILABLE" in data["reason_codes"]
    # The bundle must not claim KYC was verified when no provider was reachable.
    assert data["bundle"]["constraints"]["kyc_verified"] is False
    # And the proof artifact's compliance_evidence must reflect the failure.
    evidence = data["bundle"]["compliance_evidence"]
    kyc = next(item for item in evidence if item["check"] == "kyc")
    assert kyc["status"] == "unavailable"
    assert kyc["provider_id"].startswith("null:")


def test_permit_endpoint_records_sanctions_unavailable_status():
    with patch.object(config, "SANCTIONS_PROVIDER", "null"):
        response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})

    data = response.json()
    assert data["decision_result"] == "deny"
    assert data["bundle"]["constraints"]["sanctions_check"] == "unavailable"
    assert "SANCTIONS_PROVIDER_UNAVAILABLE" in data["reason_codes"]
    # The provider-derived screen reason code is also surfaced so the
    # permit response makes the sanctions outcome explicit, regardless
    # of how the engine collapsed it into the overall decision.
    assert "SANCTIONS_SCREEN_UNAVAILABLE" in data["reason_codes"]
    # Proof artifact also carries the screen reason code.
    assert "SANCTIONS_SCREEN_UNAVAILABLE" in data["proof_artifact"]["reason_codes"]


def test_permit_endpoint_emits_sanctions_screen_passed_reason_code():
    """The successful sanctions outcome surfaces a provider-derived
    SANCTIONS_SCREEN_PASSED reason code in addition to the legacy
    SANCTIONS_PASSED code, and the screen evidence reference is wired
    into the bundle attestations and the proof artifact."""
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "allow"
    assert "SANCTIONS_SCREEN_PASSED" in data["reason_codes"]
    assert "SANCTIONS_SCREEN_DENIED" not in data["reason_codes"]
    assert "SANCTIONS_SCREEN_UNAVAILABLE" not in data["reason_codes"]

    # Sanctions evidence reference must be surfaced as a first-class
    # attestation so consumers do not have to walk the evidence list to
    # find it, and it must match the provider-reported reference.
    sanctions_ev = next(
        item for item in data["bundle"]["compliance_evidence"]
        if item["check"] == "sanctions"
    )
    assert data["bundle"]["attestations"]["sanctions_reference"] == sanctions_ev[
        "reference"
    ]

    # Proof artifact carries the screen code and the same sanctions
    # evidence (so persisted artifacts always include the normalized
    # sanctions evidence reference).
    proof = data["proof_artifact"]
    assert "SANCTIONS_SCREEN_PASSED" in proof["reason_codes"]
    proof_evidence = proof["evaluation_context"]["compliance_evidence"]
    proof_sanctions = next(
        item for item in proof_evidence if item["check"] == "sanctions"
    )
    assert proof_sanctions["reference"] == sanctions_ev["reference"]


def test_permit_endpoint_emits_sanctions_screen_denied_when_provider_denies():
    """A provider-level deny propagates into the SANCTIONS_SCREEN_DENIED
    reason code and a denied permit decision."""
    from app.services.compliance.providers import _StaticAllowProvider
    from app.services.compliance import ProviderResult, ProviderStatus as PS

    class _DenySanctions(_StaticAllowProvider):
        def evaluate(self, context):  # noqa: ARG002
            return ProviderResult(
                check="sanctions",
                status=PS.DENIED,
                provider_id="test:deny",
                reference="case-deny-1",
                reason="ofac_match",
            )

    with patch(
        "app.services.compliance.engine._default_providers",
        return_value={
            "kyc": _StaticAllowProvider("kyc"),
            "sanctions": _DenySanctions("sanctions"),
            "reserve": _StaticAllowProvider("reserve"),
        },
    ):
        response = client.post(
            "/v1/permit",
            json={"subject": VALID_SUBJECT, "counterparty": VALID_SUBJECT},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "deny"
    assert "SANCTIONS_HIT" in data["reason_codes"]
    assert "SANCTIONS_SCREEN_DENIED" in data["reason_codes"]
    assert data["bundle"]["constraints"]["sanctions_check"] == "denied"
    # Sanctions evidence reference is preserved on the proof artifact
    # even though the decision was a denial.
    assert data["bundle"]["attestations"]["sanctions_reference"] == "case-deny-1"


# ---------------------------------------------------------------------------
# Reserve / liquidity component evaluation for regulated stablecoin flows
# ---------------------------------------------------------------------------


def test_engine_emits_reserve_and_liquidity_component_reason_codes_on_approval():
    """When the reserve provider approves both components, the engine
    surfaces RESERVE_VERIFIED and LIQUIDITY_VERIFIED in addition to the
    legacy RESERVE_BACKED token, so the permit response carries the
    explicit per-component vocabulary required by the regulated
    stablecoin permit contract."""
    with patch.object(config, "RESERVE_PROVIDER", "static_allow"):
        evaluation = evaluate_compliance(
            subject=VALID_SUBJECT,
            action="transfer",
            amount=10,
            counterparty=None,
            asset={"classification": "regulated_stablecoin"},
        )
    assert evaluation.decision == "allow"
    assert "RESERVE_VERIFIED" in evaluation.reason_codes
    assert "LIQUIDITY_VERIFIED" in evaluation.reason_codes
    # Legacy RESERVE_BACKED is preserved for backward compatibility.
    assert "RESERVE_BACKED" in evaluation.reason_codes


def test_engine_denies_regulated_stablecoin_when_liquidity_component_denied():
    """A reserve provider that approves reserves but denies liquidity
    must block a regulated_stablecoin permit and emit
    LIQUIDITY_NOT_VERIFIED + RESERVE_VERIFIED so the failure is fully
    traceable to the liquidity attestation."""

    class _PartialReserveProvider(_StaticAllowProvider):
        def evaluate(self, context):  # noqa: ARG002
            return ProviderResult(
                check="reserve",
                status=ProviderStatus.APPROVED,
                provider_id="test:partial",
                reference="ref-r-1",
                details={
                    "reserve_status": "approved",
                    "liquidity_status": "denied",
                    "liquidity_reference": "ref-l-1",
                },
            )

    evaluation = evaluate_compliance(
        subject=VALID_SUBJECT,
        action="transfer",
        amount=10,
        counterparty=None,
        asset={"classification": "regulated_stablecoin"},
        providers={
            "kyc": _StaticAllowProvider("kyc"),
            "sanctions": _StaticAllowProvider("sanctions"),
            "reserve": _PartialReserveProvider("reserve"),
        },
    )
    assert evaluation.decision == "deny"
    assert "RESERVE_VERIFIED" in evaluation.reason_codes
    assert "LIQUIDITY_NOT_VERIFIED" in evaluation.reason_codes


def test_engine_emits_evidence_unavailable_when_reserve_provider_unavailable():
    with patch.object(config, "RESERVE_PROVIDER", "null"), patch.object(
        config, "FAIL_CLOSED_COMPLIANCE", True
    ):
        evaluation = evaluate_compliance(
            subject=VALID_SUBJECT,
            action="transfer",
            amount=10,
            counterparty=None,
            asset={"classification": "regulated_stablecoin"},
        )
    assert evaluation.decision == "deny"
    assert "RESERVE_EVIDENCE_UNAVAILABLE" in evaluation.reason_codes
    assert "LIQUIDITY_EVIDENCE_UNAVAILABLE" in evaluation.reason_codes


def test_permit_endpoint_surfaces_liquidity_reference_and_summary_status():
    """The permit bundle, summary and proof artifact must carry distinct
    reserve and liquidity references derived from real provider
    evidence, and the proof artifact's evaluation_context must include
    those references for downstream auditors."""
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "allow"

    # Bundle attestations carry separate reserve and liquidity
    # references derived from the real provider evidence.
    attestations = data["bundle"]["attestations"]
    assert "reserve_reference" in attestations
    assert "liquidity_reference" in attestations
    assert attestations["reserve_reference"] is not None
    assert attestations["liquidity_reference"] is not None

    # Summary surfaces both component statuses.
    assert data["summary"]["reserve_status"] == "approved"
    assert data["summary"]["liquidity_status"] == "approved"

    # Proof artifact evaluation_context includes both references so
    # downstream auditors can resolve them without parsing the raw
    # compliance_evidence list.
    proof_ctx = data["proof_artifact"]["evaluation_context"]
    assert proof_ctx["reserve_reference"] == attestations["reserve_reference"]
    assert proof_ctx["liquidity_reference"] == attestations["liquidity_reference"]

