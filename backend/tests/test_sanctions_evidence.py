"""Tests for the sanctions screening evidence persistence model."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core import config
from app.db.session import Base
from app.db_models import SanctionsEvidenceRecord
from app.repositories.sanctions_evidence_repository import (
    create_sanctions_evidence_record,
    get_sanctions_evidence_by_bundle_hash,
)
from app.services import storage_service
from app.services.storage_service import (
    _extract_sanctions_evidence_fields,
    save_sanctions_evidence,
)


# ---------------------------------------------------------------------------
# _extract_sanctions_evidence_fields
# ---------------------------------------------------------------------------


def test_extract_uses_real_provider_reference_not_random_hash():
    evidence = {
        "check": "sanctions",
        "status": "approved",
        "provider_id": "http:sanctions",
        "reference": "case-42",
        "reason": "ok",
        "checked_at": 1700000000,
        "details": {
            "matches": [],
            "raw_response_excerpt": {"status": "clear", "matches": []},
        },
    }

    fields = _extract_sanctions_evidence_fields(
        evidence_item=evidence, subject="rExample", jurisdiction="US"
    )

    assert fields["provider_name"] == "http:sanctions"
    assert fields["subject"] == "rExample"
    assert fields["jurisdiction"] == "US"
    assert fields["sanctions_status"] == "approved"
    assert fields["evidence_reference"] == "case-42"
    assert fields["checked_at"] == 1700000000
    assert fields["evidence_payload"]["status"] == "approved"
    # The bounded raw response excerpt is preserved as part of the
    # normalized payload (auditors can see what the provider returned).
    assert (
        fields["evidence_payload"]["details"]["raw_response_excerpt"]["status"]
        == "clear"
    )


def test_extract_handles_unavailable_evidence_without_reference():
    evidence = {
        "check": "sanctions",
        "status": "unavailable",
        "provider_id": "null:sanctions",
        "reference": None,
        "reason": "no_provider_configured",
        "checked_at": 0,
        "details": {},
    }

    fields = _extract_sanctions_evidence_fields(
        evidence_item=evidence, subject="rExample", jurisdiction="US"
    )

    # No real attestation -> no reference. Critically: never a random hash.
    assert fields["evidence_reference"] is None
    assert fields["sanctions_status"] == "unavailable"
    assert fields["provider_name"] == "null:sanctions"


def test_extract_does_not_pull_in_unknown_top_level_fields():
    """The normalized payload must only carry safe normalized metadata.

    If a provider hypothetically attached a stray secret-looking value
    at the top level of the evidence dict (e.g. ``api_key``), the
    extractor must not propagate it. Only ``check`` / ``status`` /
    ``reason`` / ``details`` are persisted.
    """
    evidence = {
        "check": "sanctions",
        "status": "approved",
        "provider_id": "http:sanctions",
        "reference": "case-1",
        "checked_at": 1,
        "details": {"matches": []},
        # These would be policy violations if a provider ever produced
        # them. The extractor must drop them.
        "api_key": "sk_live_secret_should_never_be_persisted",
        "authorization_header": "Bearer secret",
    }

    fields = _extract_sanctions_evidence_fields(
        evidence_item=evidence, subject="r", jurisdiction=""
    )

    payload = fields["evidence_payload"]
    assert "api_key" not in payload
    assert "authorization_header" not in payload
    assert set(payload.keys()) == {"check", "status", "reason", "details"}


# ---------------------------------------------------------------------------
# save_sanctions_evidence – persistence-disabled & no-op behaviour
# ---------------------------------------------------------------------------


def test_save_sanctions_evidence_noop_when_persistence_disabled():
    with patch.object(config, "DATABASE_URL", ""):
        save_sanctions_evidence(
            bundle_hash="abc",
            evidence_item={
                "check": "sanctions",
                "status": "approved",
                "provider_id": "http:sanctions",
                "reference": "case-1",
                "checked_at": 1,
                "details": {},
            },
            subject="r",
            jurisdiction="US",
        )


def test_save_sanctions_evidence_noop_when_no_evidence():
    with patch.object(storage_service, "persistence_enabled", lambda: True):
        save_sanctions_evidence(
            bundle_hash="abc",
            evidence_item=None,
            subject="r",
            jurisdiction="US",
        )


def test_save_sanctions_evidence_ignores_non_sanctions_check():
    with patch.object(storage_service, "persistence_enabled", lambda: True):
        save_sanctions_evidence(
            bundle_hash="abc",
            evidence_item={
                "check": "kyc",
                "status": "approved",
                "provider_id": "http:kyc",
                "reference": "kyc-1",
                "checked_at": 1,
                "details": {},
            },
            subject="r",
            jurisdiction="US",
        )


# ---------------------------------------------------------------------------
# Repository round-trip against an in-memory SQLite database
# ---------------------------------------------------------------------------


@pytest.fixture()
def sqlite_session():
    engine = create_engine("sqlite://", future=True)
    Base.metadata.create_all(bind=engine)
    session = Session(bind=engine, future=True)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def test_repository_create_and_lookup(sqlite_session):
    create_sanctions_evidence_record(
        session=sqlite_session,
        bundle_hash="hash-1",
        provider_name="http:sanctions",
        subject="rExample",
        jurisdiction="US",
        sanctions_status="approved",
        evidence_reference="case-1",
        checked_at=1700000000,
        evidence_payload={"status": "approved", "details": {"matches": []}},
    )
    sqlite_session.commit()

    rows = get_sanctions_evidence_by_bundle_hash(
        session=sqlite_session, bundle_hash="hash-1"
    )
    assert len(rows) == 1
    row = rows[0]
    assert isinstance(row, SanctionsEvidenceRecord)
    assert row.provider_name == "http:sanctions"
    assert row.subject == "rExample"
    assert row.jurisdiction == "US"
    assert row.sanctions_status == "approved"
    assert row.evidence_reference == "case-1"
    assert row.checked_at == 1700000000
    assert row.evidence_payload_json == {
        "status": "approved",
        "details": {"matches": []},
    }
    assert row.id  # uuid generated


def test_save_sanctions_evidence_persists_via_explicit_session(sqlite_session):
    with patch.object(storage_service, "persistence_enabled", lambda: True):
        save_sanctions_evidence(
            bundle_hash="hash-2",
            evidence_item={
                "check": "sanctions",
                "status": "denied",
                "provider_id": "http:sanctions",
                "reference": "case-2",
                "reason": "match",
                "checked_at": 1700000123,
                "details": {"matches": [{"list": "ofac_sdn"}]},
            },
            subject="rExample",
            jurisdiction="US",
            db=sqlite_session,
        )

    rows = get_sanctions_evidence_by_bundle_hash(
        session=sqlite_session, bundle_hash="hash-2"
    )
    assert len(rows) == 1
    row = rows[0]
    assert row.sanctions_status == "denied"
    assert row.evidence_reference == "case-2"
    assert row.evidence_payload_json["reason"] == "match"
    assert row.evidence_payload_json["details"]["matches"][0]["list"] == "ofac_sdn"
