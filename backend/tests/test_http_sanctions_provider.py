"""Tests for the concrete HTTP-backed sanctions screening provider."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from app.core import config
from app.services.compliance import evaluate_compliance
from app.services.compliance.providers import _AddressScreenSanctionsProvider
from app.services.providers import (
    HttpSanctionsProvider,
    NotConfiguredSanctionsProvider,
    ProviderDecision,
    ProviderStatus,
    build_sanctions_provider_from_config,
)


VALID_SUBJECT = "rN7n3473SaZBCG4dFL83w7PB5XDnEHyMQX"
VALID_DESTINATION = "rDESTINATION_WALLET_ADDRESS_FOR_TESTS"


class _FakeResponse:
    def __init__(self, *, status_code: int = 200, body: Any = None, raise_decode: bool = False):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self._raise_decode = raise_decode
        self.url = "https://provider.example/screen"

    def json(self) -> Any:
        if self._raise_decode:
            raise ValueError("not json")
        return self._body


def _make_fetcher(*responses_or_factory):
    """Build a fetcher returning successive ``_FakeResponse`` objects.

    ``responses_or_factory`` may be either a list of ``_FakeResponse``
    instances or a callable ``(payload) -> _FakeResponse`` for tests
    that need to inspect the request payload.
    """
    if len(responses_or_factory) == 1 and callable(responses_or_factory[0]):
        factory = responses_or_factory[0]
        calls: list[dict[str, Any]] = []

        def fetcher(url, payload, headers, timeout):  # noqa: ARG001
            calls.append({"url": url, "payload": payload, "headers": headers, "timeout": timeout})
            return factory(payload)

        fetcher.calls = calls  # type: ignore[attr-defined]
        return fetcher

    queue = list(responses_or_factory)
    calls: list[dict[str, Any]] = []

    def fetcher(url, payload, headers, timeout):  # noqa: ARG001
        calls.append({"url": url, "payload": payload, "headers": headers, "timeout": timeout})
        if not queue:
            raise AssertionError("fetcher called more times than expected")
        return queue.pop(0)

    fetcher.calls = calls  # type: ignore[attr-defined]
    return fetcher


# ---------------------------------------------------------------------------
# Configuration / wiring
# ---------------------------------------------------------------------------


def test_http_sanctions_provider_reports_configured_state():
    provider = HttpSanctionsProvider(
        provider_name="acme",
        url="https://acme.example/screen",
        api_key="k",
        fetcher=_make_fetcher(_FakeResponse(body={"decision": "pass"})),
    )
    assert provider.is_configured() is True
    assert provider.provider_name == "sanctions:acme"


def test_http_sanctions_provider_unavailable_when_url_missing():
    provider = HttpSanctionsProvider(provider_name="acme", url="", api_key="k")
    result = provider.screen(subject=VALID_SUBJECT)
    assert result.decision is ProviderDecision.UNAVAILABLE
    assert result.status is ProviderStatus.NOT_CONFIGURED
    assert "SANCTIONS_PROVIDER_NOT_CONFIGURED" in result.reason_codes
    # Evidence excerpt must not contain the API key.
    assert result.raw_response_excerpt is not None
    assert "k" not in str(result.raw_response_excerpt.values())


def test_build_sanctions_provider_from_config_uses_not_configured_when_blank(monkeypatch):
    monkeypatch.setattr(config, "SANCTIONS_PROVIDER", "null", raising=False)
    monkeypatch.setattr(config, "SANCTIONS_PROVIDER_URL", "", raising=False)
    monkeypatch.setattr(config, "SANCTIONS_API_KEY", "", raising=False)
    provider = build_sanctions_provider_from_config()
    assert isinstance(provider, NotConfiguredSanctionsProvider)


def test_build_sanctions_provider_from_config_uses_http_when_configured(monkeypatch):
    monkeypatch.setattr(config, "SANCTIONS_PROVIDER", "chainalysis", raising=False)
    monkeypatch.setattr(
        config, "SANCTIONS_PROVIDER_URL", "https://api.chainalysis.example/screen", raising=False
    )
    monkeypatch.setattr(config, "SANCTIONS_API_KEY", "secret-key", raising=False)
    provider = build_sanctions_provider_from_config()
    assert isinstance(provider, HttpSanctionsProvider)
    assert provider.provider_name == "sanctions:chainalysis"


# ---------------------------------------------------------------------------
# Real HTTP screening behaviour
# ---------------------------------------------------------------------------


def test_screen_subject_only_sends_one_call_with_authorization_header():
    fetcher = _make_fetcher(_FakeResponse(body={"decision": "pass"}))
    provider = HttpSanctionsProvider(
        provider_name="acme",
        url="https://acme.example/screen",
        api_key="super-secret",
        fetcher=fetcher,
    )

    result = provider.screen(subject=VALID_SUBJECT, context={"jurisdiction": "US"})

    assert len(fetcher.calls) == 1
    call = fetcher.calls[0]
    assert call["payload"]["address"] == VALID_SUBJECT
    assert call["payload"]["role"] == "subject"
    assert call["payload"]["jurisdiction"] == "US"
    assert call["headers"]["Authorization"] == "Bearer super-secret"

    assert result.decision is ProviderDecision.PASS
    assert result.status is ProviderStatus.OK
    assert "SANCTIONS_NO_HITS" in result.reason_codes


def test_screen_also_screens_destination_wallet_when_provided():
    fetcher = _make_fetcher(
        _FakeResponse(body={"decision": "pass"}),
        _FakeResponse(body={"decision": "pass"}),
    )
    provider = HttpSanctionsProvider(
        provider_name="acme",
        url="https://acme.example/screen",
        api_key="k",
        fetcher=fetcher,
    )

    result = provider.screen(
        subject=VALID_SUBJECT,
        context={"destination": VALID_DESTINATION},
    )

    assert len(fetcher.calls) == 2
    roles = {c["payload"]["role"] for c in fetcher.calls}
    assert roles == {"subject", "destination"}
    assert result.decision is ProviderDecision.PASS


def test_screen_does_not_double_screen_same_address():
    fetcher = _make_fetcher(_FakeResponse(body={"decision": "pass"}))
    provider = HttpSanctionsProvider(
        provider_name="acme",
        url="https://acme.example/screen",
        api_key="k",
        fetcher=fetcher,
    )

    result = provider.screen(
        subject=VALID_SUBJECT,
        context={"destination": VALID_SUBJECT},
    )
    assert len(fetcher.calls) == 1
    assert result.decision is ProviderDecision.PASS


def test_screen_returns_deny_with_per_list_reason_codes():
    body = {
        "decision": "deny",
        "reference": "case-42",
        "hits": [
            {"list": "OFAC SDN", "name": "Sanctioned Person", "severity": "strong"},
            {"list": "EU Consolidated", "name": "Sanctioned Entity", "severity": "strong"},
        ],
    }
    provider = HttpSanctionsProvider(
        provider_name="acme",
        url="https://acme.example/screen",
        api_key="k",
        fetcher=_make_fetcher(_FakeResponse(body=body)),
    )

    result = provider.screen(subject=VALID_SUBJECT)

    assert result.decision is ProviderDecision.DENY
    assert "SANCTIONS_HIT_OFAC_SDN" in result.reason_codes
    assert "SANCTIONS_HIT_EU_CONSOLIDATED" in result.reason_codes
    assert result.evidence_reference == "case-42"
    excerpt = result.raw_response_excerpt or {}
    screened = excerpt["screened"]
    assert screened[0]["details"]["hit_count"] == 2


def test_screen_returns_review_for_potential_match():
    body = {"decision": "potential_match", "score": 0.6}
    provider = HttpSanctionsProvider(
        provider_name="acme",
        url="https://acme.example/screen",
        api_key="k",
        fetcher=_make_fetcher(_FakeResponse(body=body)),
    )
    result = provider.screen(subject=VALID_SUBJECT)
    assert result.decision is ProviderDecision.REVIEW
    assert "SANCTIONS_POTENTIAL_MATCH" in result.reason_codes


def test_screen_review_is_inferred_from_weak_hits_when_no_decision_field():
    body = {"hits": [{"list": "PEP", "severity": "weak"}]}
    provider = HttpSanctionsProvider(
        provider_name="acme",
        url="https://acme.example/screen",
        api_key="k",
        fetcher=_make_fetcher(_FakeResponse(body=body)),
    )
    result = provider.screen(subject=VALID_SUBJECT)
    assert result.decision is ProviderDecision.REVIEW


def test_screen_returns_unavailable_on_indeterminate_response():
    """No decision, no hits, no recognizable status -> never default to pass."""
    provider = HttpSanctionsProvider(
        provider_name="acme",
        url="https://acme.example/screen",
        api_key="k",
        fetcher=_make_fetcher(_FakeResponse(body={"foo": "bar"})),
    )
    result = provider.screen(subject=VALID_SUBJECT)
    assert result.decision is ProviderDecision.UNAVAILABLE
    assert result.status is ProviderStatus.ERROR


def test_screen_returns_unavailable_on_transport_error():
    def boom(url, payload, headers, timeout):  # noqa: ARG001
        raise ConnectionError("network down")

    provider = HttpSanctionsProvider(
        provider_name="acme",
        url="https://acme.example/screen",
        api_key="k",
        fetcher=boom,
    )
    result = provider.screen(subject=VALID_SUBJECT)
    assert result.decision is ProviderDecision.UNAVAILABLE
    assert result.status is ProviderStatus.ERROR
    assert any(code.startswith("SANCTIONS_PROVIDER_") for code in result.reason_codes)


def test_screen_returns_unavailable_on_http_5xx():
    provider = HttpSanctionsProvider(
        provider_name="acme",
        url="https://acme.example/screen",
        api_key="k",
        fetcher=_make_fetcher(_FakeResponse(status_code=503, body={"err": "oops"})),
    )
    result = provider.screen(subject=VALID_SUBJECT)
    assert result.decision is ProviderDecision.UNAVAILABLE


def test_screen_returns_unavailable_on_invalid_json():
    provider = HttpSanctionsProvider(
        provider_name="acme",
        url="https://acme.example/screen",
        api_key="k",
        fetcher=_make_fetcher(_FakeResponse(raise_decode=True)),
    )
    result = provider.screen(subject=VALID_SUBJECT)
    assert result.decision is ProviderDecision.UNAVAILABLE


def test_destination_unavailable_does_not_silently_pass_subject():
    """Subject is clean but destination call fails -> overall unavailable."""
    fetcher = _make_fetcher(
        _FakeResponse(body={"decision": "pass"}),
        _FakeResponse(status_code=500, body={}),
    )
    provider = HttpSanctionsProvider(
        provider_name="acme",
        url="https://acme.example/screen",
        api_key="k",
        fetcher=fetcher,
    )
    result = provider.screen(
        subject=VALID_SUBJECT,
        context={"destination": VALID_DESTINATION},
    )
    assert result.decision is ProviderDecision.UNAVAILABLE


def test_destination_deny_overrides_subject_pass():
    fetcher = _make_fetcher(
        _FakeResponse(body={"decision": "pass"}),
        _FakeResponse(body={"decision": "deny", "hits": [{"list": "OFAC"}]}),
    )
    provider = HttpSanctionsProvider(
        provider_name="acme",
        url="https://acme.example/screen",
        api_key="k",
        fetcher=fetcher,
    )
    result = provider.screen(
        subject=VALID_SUBJECT,
        context={"destination": VALID_DESTINATION},
    )
    assert result.decision is ProviderDecision.DENY


def test_evidence_excerpt_does_not_contain_api_key_or_authorization_header():
    fetcher = _make_fetcher(_FakeResponse(body={"decision": "pass"}))
    provider = HttpSanctionsProvider(
        provider_name="acme",
        url="https://acme.example/screen?api_key=should-not-leak",
        api_key="super-secret-key",
        fetcher=fetcher,
    )
    result = provider.screen(subject=VALID_SUBJECT)
    serialized = str(result.to_dict())
    assert "super-secret-key" not in serialized
    assert "Authorization" not in serialized
    # The query string with the secret-looking parameter must be stripped.
    assert "should-not-leak" not in serialized


# ---------------------------------------------------------------------------
# Engine integration: fail-closed permit denial via address_screen kind
# ---------------------------------------------------------------------------


def test_engine_address_screen_denies_when_provider_unavailable_and_fail_closed(monkeypatch):
    """Provider unavailable + FAIL_CLOSED_COMPLIANCE=true -> permit denied."""
    monkeypatch.setattr(config, "SANCTIONS_PROVIDER", "acme", raising=False)
    monkeypatch.setattr(
        config, "SANCTIONS_PROVIDER_URL", "https://acme.example/screen", raising=False
    )
    monkeypatch.setattr(config, "SANCTIONS_API_KEY", "k", raising=False)
    monkeypatch.setattr(config, "FAIL_CLOSED_COMPLIANCE", True, raising=False)

    def unavailable_factory():
        return HttpSanctionsProvider(
            provider_name="acme",
            url="https://acme.example/screen",
            api_key="k",
            fetcher=_make_fetcher(_FakeResponse(status_code=503, body={})),
        )

    adapter = _AddressScreenSanctionsProvider(provider_factory=unavailable_factory)
    evaluation = evaluate_compliance(
        subject=VALID_SUBJECT,
        action="transfer",
        amount=10,
        counterparty=None,
        providers={
            "kyc": _build_static_kyc(),
            "sanctions": adapter,
            "reserve": _build_static_reserve(),
        },
    )

    assert evaluation.decision == "deny"
    assert "SANCTIONS_PROVIDER_UNAVAILABLE" in evaluation.reason_codes
    sanctions_evidence = next(
        item for item in evaluation.evidence if item["check"] == "sanctions"
    )
    assert sanctions_evidence["provider_id"].startswith("address_screen:sanctions:")
    assert sanctions_evidence["status"] == "unavailable"
    # Normalized details are recorded for audit.
    assert sanctions_evidence["details"]["decision"] == "unavailable"


def test_engine_address_screen_denies_on_explicit_hit():
    def deny_factory():
        return HttpSanctionsProvider(
            provider_name="acme",
            url="https://acme.example/screen",
            api_key="k",
            fetcher=_make_fetcher(
                _FakeResponse(
                    body={
                        "decision": "deny",
                        "reference": "case-99",
                        "hits": [{"list": "OFAC SDN", "severity": "strong"}],
                    }
                )
            ),
        )

    adapter = _AddressScreenSanctionsProvider(provider_factory=deny_factory)
    evaluation = evaluate_compliance(
        subject=VALID_SUBJECT,
        action="transfer",
        amount=10,
        counterparty=None,
        providers={
            "kyc": _build_static_kyc(),
            "sanctions": adapter,
            "reserve": _build_static_reserve(),
        },
    )
    assert evaluation.decision == "deny"
    assert "SANCTIONS_HIT" in evaluation.reason_codes
    sanctions_result = evaluation.results["sanctions"]
    assert sanctions_result.reference == "case-99"


def test_engine_address_screen_passes_through_clean_screen():
    def pass_factory():
        return HttpSanctionsProvider(
            provider_name="acme",
            url="https://acme.example/screen",
            api_key="k",
            fetcher=_make_fetcher(_FakeResponse(body={"decision": "pass"})),
        )

    adapter = _AddressScreenSanctionsProvider(provider_factory=pass_factory)
    evaluation = evaluate_compliance(
        subject=VALID_SUBJECT,
        action="transfer",
        amount=10,
        counterparty=None,
        providers={
            "kyc": _build_static_kyc(),
            "sanctions": adapter,
            "reserve": _build_static_reserve(),
        },
    )
    assert evaluation.decision == "allow"
    assert "SANCTIONS_PASSED" in evaluation.reason_codes


def test_engine_address_screen_review_outcome_fails_closed():
    """Review = manual hold; engine must deny (deny / conditional deny
    for MVP) rather than auto-issue a permit, and the persisted evidence
    must make it clear the denial came from a review escalation."""
    def review_factory():
        return HttpSanctionsProvider(
            provider_name="acme",
            url="https://acme.example/screen",
            api_key="k",
            fetcher=_make_fetcher(_FakeResponse(body={"decision": "review"})),
        )

    adapter = _AddressScreenSanctionsProvider(provider_factory=review_factory)
    with patch.object(config, "FAIL_CLOSED_COMPLIANCE", True):
        evaluation = evaluate_compliance(
            subject=VALID_SUBJECT,
            action="transfer",
            amount=10,
            counterparty=None,
            providers={
                "kyc": _build_static_kyc(),
                "sanctions": adapter,
                "reserve": _build_static_reserve(),
            },
        )
    assert evaluation.decision == "deny"
    # Review collapses to a denial for MVP, so the denial-shaped reason
    # codes are emitted (not the unavailable ones).
    assert "SANCTIONS_HIT" in evaluation.reason_codes
    assert "SANCTIONS_SCREEN_DENIED" in evaluation.reason_codes
    assert "SANCTIONS_PROVIDER_UNAVAILABLE" not in evaluation.reason_codes

    sanctions_evidence = next(
        item for item in evaluation.evidence if item["check"] == "sanctions"
    )
    assert sanctions_evidence["status"] == "denied"
    # The original "review" outcome must still be traceable in the
    # persisted evidence so auditors can see *why* the denial happened.
    assert sanctions_evidence["details"]["decision"] == "review"
    assert sanctions_evidence["details"]["review_denied_for_mvp"] is True
    assert sanctions_evidence["reason"] == "SANCTIONS_REVIEW_DENIED_FOR_MVP"


def test_engine_address_screen_kind_is_built_via_factory(monkeypatch):
    monkeypatch.setattr(config, "SANCTIONS_PROVIDER", "address_screen", raising=False)
    from app.services.compliance.providers import get_sanctions_provider

    provider = get_sanctions_provider()
    assert isinstance(provider, _AddressScreenSanctionsProvider)


def test_address_screen_kind_for_non_sanctions_check_falls_back_to_null(monkeypatch):
    from app.services.compliance.providers import _NullProvider, get_kyc_provider

    monkeypatch.setattr(config, "KYC_PROVIDER", "address_screen", raising=False)
    provider = get_kyc_provider()
    assert isinstance(provider, _NullProvider)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_static_kyc():
    from app.services.compliance.providers import _StaticAllowProvider

    return _StaticAllowProvider("kyc")


def _build_static_reserve():
    from app.services.compliance.providers import _StaticAllowProvider

    return _StaticAllowProvider("reserve")
