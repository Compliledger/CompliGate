"""Tests for the reserve / liquidity evidence persistence model."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core import config
from app.db.session import Base
from app.db_models import ReserveEvidenceRecord
from app.repositories.reserve_evidence_repository import (
    create_reserve_evidence_record,
    get_reserve_evidence_by_bundle_hash,
)
from app.services import storage_service
from app.services.storage_service import (
    _extract_reserve_evidence_fields,
    save_reserve_evidence,
)


# ---------------------------------------------------------------------------
# _extract_reserve_evidence_fields
# ---------------------------------------------------------------------------


def test_extract_uses_real_provider_reference_not_random_hash():
    evidence = {
        "check": "reserve",
        "status": "approved",
        "provider_id": "http:reserve",
        "reference": "att-12345",
        "reason": "ok",
        "checked_at": 1700000000,
        "details": {"signature_reference": "0xabc123"},
    }

    fields = _extract_reserve_evidence_fields(
        evidence_item=evidence, asset="RLUSD", issuer="rIssuer"
    )

    assert fields["provider_name"] == "http:reserve"
    assert fields["asset"] == "RLUSD"
    assert fields["issuer"] == "rIssuer"
    assert fields["attestation_reference"] == "att-12345"
    assert fields["reserve_status"] == "approved"
    assert fields["liquidity_status"] == "approved"
    assert fields["checked_at"] == 1700000000
    assert fields["signature_reference"] == "0xabc123"
    assert fields["evidence_payload"]["status"] == "approved"
    assert fields["evidence_payload"]["details"]["signature_reference"] == "0xabc123"


def test_extract_preserves_distinct_reserve_and_liquidity_status():
    evidence = {
        "check": "reserve",
        "status": "approved",
        "provider_id": "http:reserve",
        "reference": "att-1",
        "checked_at": 100,
        "details": {
            "reserve_status": "approved",
            "liquidity_status": "denied",
        },
    }

    fields = _extract_reserve_evidence_fields(
        evidence_item=evidence, asset="USD", issuer=""
    )

    assert fields["reserve_status"] == "approved"
    assert fields["liquidity_status"] == "denied"


def test_extract_handles_unavailable_evidence_without_reference():
    evidence = {
        "check": "reserve",
        "status": "unavailable",
        "provider_id": "null:reserve",
        "reference": None,
        "reason": "no_provider_configured",
        "checked_at": 0,
        "details": {},
    }

    fields = _extract_reserve_evidence_fields(
        evidence_item=evidence, asset="USD", issuer="rIssuer"
    )

    # No real attestation -> no reference. Critically: never a random hash.
    assert fields["attestation_reference"] is None
    assert fields["reserve_status"] == "unavailable"
    assert fields["liquidity_status"] == "unavailable"
    assert fields["signature_reference"] is None


# ---------------------------------------------------------------------------
# save_reserve_evidence – persistence-disabled & no-op behaviour
# ---------------------------------------------------------------------------


def test_save_reserve_evidence_noop_when_persistence_disabled():
    with patch.object(config, "DATABASE_URL", ""):
        # Must not raise even though no engine is configured.
        save_reserve_evidence(
            bundle_hash="abc",
            evidence_item={
                "check": "reserve",
                "status": "approved",
                "provider_id": "http:reserve",
                "reference": "att-1",
                "checked_at": 1,
                "details": {},
            },
            asset="USD",
            issuer="rIssuer",
        )


def test_save_reserve_evidence_noop_when_no_evidence():
    with patch.object(storage_service, "persistence_enabled", lambda: True):
        # Should short-circuit before trying to open a session.
        save_reserve_evidence(
            bundle_hash="abc",
            evidence_item=None,
            asset="USD",
            issuer="rIssuer",
        )


def test_save_reserve_evidence_ignores_non_reserve_check():
    with patch.object(storage_service, "persistence_enabled", lambda: True):
        save_reserve_evidence(
            bundle_hash="abc",
            evidence_item={
                "check": "kyc",
                "status": "approved",
                "provider_id": "http:kyc",
                "reference": "kyc-1",
                "checked_at": 1,
                "details": {},
            },
            asset="USD",
            issuer="rIssuer",
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
    create_reserve_evidence_record(
        session=sqlite_session,
        bundle_hash="hash-1",
        provider_name="http:reserve",
        asset="RLUSD",
        issuer="rIssuer",
        attestation_reference="att-1",
        reserve_status="approved",
        liquidity_status="approved",
        checked_at=1700000000,
        evidence_payload={"status": "approved", "details": {"x": 1}},
        signature_reference="0xdeadbeef",
    )
    sqlite_session.commit()

    rows = get_reserve_evidence_by_bundle_hash(session=sqlite_session, bundle_hash="hash-1")
    assert len(rows) == 1
    row = rows[0]
    assert isinstance(row, ReserveEvidenceRecord)
    assert row.provider_name == "http:reserve"
    assert row.asset == "RLUSD"
    assert row.issuer == "rIssuer"
    assert row.attestation_reference == "att-1"
    assert row.reserve_status == "approved"
    assert row.liquidity_status == "approved"
    assert row.checked_at == 1700000000
    assert row.evidence_payload_json == {"status": "approved", "details": {"x": 1}}
    assert row.signature_reference == "0xdeadbeef"
    assert row.id  # uuid generated


def test_save_reserve_evidence_persists_via_explicit_session(sqlite_session):
    # Force persistence_enabled() to True so save_reserve_evidence proceeds.
    with patch.object(storage_service, "persistence_enabled", lambda: True):
        save_reserve_evidence(
            bundle_hash="hash-2",
            evidence_item={
                "check": "reserve",
                "status": "denied",
                "provider_id": "http:reserve",
                "reference": "att-2",
                "reason": "insufficient",
                "checked_at": 1700000123,
                "details": {"liquidity_status": "denied", "reserve_status": "denied"},
            },
            asset="RLUSD",
            issuer="rIssuer",
            db=sqlite_session,
        )

    rows = get_reserve_evidence_by_bundle_hash(session=sqlite_session, bundle_hash="hash-2")
    assert len(rows) == 1
    row = rows[0]
    assert row.reserve_status == "denied"
    assert row.liquidity_status == "denied"
    assert row.attestation_reference == "att-2"
    assert row.evidence_payload_json["reason"] == "insufficient"
