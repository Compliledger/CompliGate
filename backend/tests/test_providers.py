"""Tests for the compliance provider abstraction layer."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.services.providers import (
    PROVIDER_NOT_CONFIGURED_REASON,
    KycProvider,
    NotConfiguredKycProvider,
    NotConfiguredReserveProvider,
    NotConfiguredSanctionsProvider,
    ProviderDecision,
    ProviderResult,
    ProviderStatus,
    ReserveProvider,
    SanctionsProvider,
)


@pytest.fixture(autouse=True)
def _reset_allow_flag(monkeypatch):
    """Ensure ALLOW_UNCONFIGURED_PROVIDERS does not leak between tests."""

    monkeypatch.delenv("ALLOW_UNCONFIGURED_PROVIDERS", raising=False)
    yield


def test_provider_result_to_dict_is_json_friendly():
    result = ProviderResult(
        provider_name="sanctions:not_configured",
        status=ProviderStatus.NOT_CONFIGURED,
        decision=ProviderDecision.DENY,
        reason_codes=("PROVIDER_NOT_CONFIGURED",),
        evidence_reference=None,
        checked_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        raw_response_excerpt={"configured": False},
    )

    data = result.to_dict()

    assert data["provider_name"] == "sanctions:not_configured"
    assert data["status"] == "not_configured"
    assert data["decision"] == "deny"
    assert data["reason_codes"] == ["PROVIDER_NOT_CONFIGURED"]
    assert data["evidence_reference"] is None
    assert data["checked_at"] == "2026-01-02T03:04:05+00:00"
    assert data["raw_response_excerpt"] == {"configured": False}


def test_not_configured_sanctions_fails_closed_by_default():
    provider = NotConfiguredSanctionsProvider()

    assert isinstance(provider, SanctionsProvider)
    assert provider.is_configured() is False

    result = provider.screen(subject="rEXAMPLE", context={"jurisdiction": "US"})

    assert result.provider_name == "sanctions:not_configured"
    assert result.status is ProviderStatus.NOT_CONFIGURED
    assert result.decision is ProviderDecision.DENY
    assert PROVIDER_NOT_CONFIGURED_REASON in result.reason_codes
    assert result.raw_response_excerpt is not None
    assert result.raw_response_excerpt["subject"] == "rEXAMPLE"
    assert result.raw_response_excerpt["configured"] is False
    assert result.checked_at.tzinfo is not None


def test_not_configured_kyc_fails_closed_by_default():
    provider = NotConfiguredKycProvider()

    assert isinstance(provider, KycProvider)
    result = provider.get_status(subject="rEXAMPLE")

    assert result.provider_name == "kyc:not_configured"
    assert result.status is ProviderStatus.NOT_CONFIGURED
    assert result.decision is ProviderDecision.DENY
    assert result.reason_codes == (PROVIDER_NOT_CONFIGURED_REASON,)


def test_not_configured_reserve_fails_closed_by_default():
    provider = NotConfiguredReserveProvider()

    assert isinstance(provider, ReserveProvider)
    result = provider.get_evidence(asset="RLUSD", amount=1000)

    assert result.provider_name == "reserve:not_configured"
    assert result.status is ProviderStatus.NOT_CONFIGURED
    assert result.decision is ProviderDecision.DENY
    assert result.reason_codes == (PROVIDER_NOT_CONFIGURED_REASON,)
    assert result.raw_response_excerpt is not None
    assert result.raw_response_excerpt["asset"] == "RLUSD"
    assert result.raw_response_excerpt["amount"] == 1000


@pytest.mark.parametrize(
    ("provider_factory", "invoke"),
    [
        (NotConfiguredSanctionsProvider, lambda p: p.screen(subject="rEXAMPLE")),
        (NotConfiguredKycProvider, lambda p: p.get_status(subject="rEXAMPLE")),
        (
            NotConfiguredReserveProvider,
            lambda p: p.get_evidence(asset="RLUSD", amount=1),
        ),
    ],
)
def test_allow_unconfigured_flag_returns_allow_skipped(
    monkeypatch, provider_factory, invoke
):
    monkeypatch.setenv("ALLOW_UNCONFIGURED_PROVIDERS", "true")

    result = invoke(provider_factory())

    assert result.status is ProviderStatus.SKIPPED
    assert result.decision is ProviderDecision.ALLOW
    assert any("SKIPPED_LOCAL_DEV" in code for code in result.reason_codes)
    assert result.raw_response_excerpt is not None
    assert result.raw_response_excerpt["allow_unconfigured"] is True


@pytest.mark.parametrize(
    "value,expected_decision",
    [
        ("false", ProviderDecision.DENY),
        ("0", ProviderDecision.DENY),
        ("", ProviderDecision.DENY),
        ("true", ProviderDecision.ALLOW),
        ("1", ProviderDecision.ALLOW),
        ("YES", ProviderDecision.ALLOW),
    ],
)
def test_allow_unconfigured_flag_parsing(monkeypatch, value, expected_decision):
    monkeypatch.setenv("ALLOW_UNCONFIGURED_PROVIDERS", value)
    result = NotConfiguredSanctionsProvider().screen(subject="rEXAMPLE")
    assert result.decision is expected_decision


def test_concrete_provider_must_define_provider_name():
    class BrokenSanctions(NotConfiguredSanctionsProvider):
        provider_name = ""

    with pytest.raises(ValueError):
        BrokenSanctions().screen(subject="rEXAMPLE")
