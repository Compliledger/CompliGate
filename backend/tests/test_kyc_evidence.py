"""Tests for the KYC verification evidence persistence model."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core import config
from app.db.session import Base
from app.db_models import KycEvidenceRecord
from app.repositories.kyc_evidence_repository import (
    create_kyc_evidence_record,
    get_kyc_evidence_by_bundle_hash,
)
from app.services import storage_service
from app.services.storage_service import (
    _extract_kyc_evidence_fields,
    save_kyc_evidence,
)


# ---------------------------------------------------------------------------
# _extract_kyc_evidence_fields
# ---------------------------------------------------------------------------


def test_extract_prefers_normalized_kyc_result():
    evidence = {
        "check": "kyc",
        "status": "approved",
        "provider_id": "http:kyc",
        "reference": "kyc-engine-ref",
        "reason": "ok",
        "checked_at": 1700000000,
        "details": {
            "kyc_result": {
                "provider_name": "upstream_assertion:bank-x",
                "subject_id": "rSubject",
                "kyc_status": "verified",
                "jurisdiction": "US",
                "checked_at": 1699999999,
                "evidence_reference": "case-99",
                "reason_codes": ["KYC_VERIFIED"],
            }
        },
    }

    fields = _extract_kyc_evidence_fields(evidence_item=evidence)

    assert fields["check_type"] == "kyc"
    # Provider info comes from the normalized kyc_result block.
    assert fields["provider_name"] == "upstream_assertion:bank-x"
    assert fields["subject_id"] == "rSubject"
    assert fields["jurisdiction"] == "US"
    assert fields["evidence_reference"] == "case-99"
    assert fields["checked_at"] == 1699999999
    # Status is the normalized kyc_status, not the raw provider status.
    assert fields["kyc_status"] == "verified"
    assert fields["evidence_payload"]["status"] == "approved"
    assert fields["evidence_payload"]["details"]["kyc_result"]["jurisdiction"] == "US"


def test_extract_falls_back_to_engine_fields_when_no_kyc_result():
    evidence = {
        "check": "kyc",
        "status": "unavailable",
        "provider_id": "null:kyc",
        "reference": None,
        "reason": "no_provider_configured",
        "checked_at": 0,
        "details": {},
    }

    fields = _extract_kyc_evidence_fields(evidence_item=evidence)

    assert fields["check_type"] == "kyc"
    assert fields["provider_name"] == "null:kyc"
    assert fields["subject_id"] == ""
    assert fields["jurisdiction"] == ""
    assert fields["evidence_reference"] is None
    # Falls back to overall status when no kyc_result block is present.
    assert fields["kyc_status"] == "unavailable"


def test_extract_preserves_destination_check_type():
    evidence = {
        "check": "kyc:destination",
        "status": "approved",
        "provider_id": "http:kyc",
        "reference": "kyc-dest-1",
        "checked_at": 1,
        "details": {
            "kyc_result": {
                "provider_name": "http:kyc",
                "subject_id": "rDest",
                "kyc_status": "verified",
                "jurisdiction": "US",
                "checked_at": 1,
                "evidence_reference": "kyc-dest-1",
                "reason_codes": [],
            }
        },
    }

    fields = _extract_kyc_evidence_fields(evidence_item=evidence)

    assert fields["check_type"] == "kyc:destination"
    assert fields["subject_id"] == "rDest"
    assert fields["kyc_status"] == "verified"


def test_extract_does_not_pull_in_unknown_top_level_fields():
    """The persisted payload must not propagate stray secret-looking fields."""
    evidence = {
        "check": "kyc",
        "status": "approved",
        "provider_id": "http:kyc",
        "reference": "kyc-1",
        "checked_at": 1,
        "details": {"kyc_result": {"kyc_status": "verified"}},
        "api_key": "sk_live_secret_should_never_be_persisted",
    }

    fields = _extract_kyc_evidence_fields(evidence_item=evidence)

    assert "api_key" not in fields["evidence_payload"]
    assert set(fields["evidence_payload"].keys()) == {
        "check",
        "status",
        "reason",
        "details",
    }


# ---------------------------------------------------------------------------
# save_kyc_evidence – persistence-disabled & no-op behaviour
# ---------------------------------------------------------------------------


def test_save_kyc_evidence_noop_when_persistence_disabled():
    with patch.object(config, "DATABASE_URL", ""):
        save_kyc_evidence(
            bundle_hash="abc",
            evidence_item={
                "check": "kyc",
                "status": "approved",
                "provider_id": "http:kyc",
                "reference": "kyc-1",
                "checked_at": 1,
                "details": {},
            },
        )


def test_save_kyc_evidence_noop_when_no_evidence():
    with patch.object(storage_service, "persistence_enabled", lambda: True):
        save_kyc_evidence(bundle_hash="abc", evidence_item=None)


def test_save_kyc_evidence_ignores_non_kyc_check():
    with patch.object(storage_service, "persistence_enabled", lambda: True):
        save_kyc_evidence(
            bundle_hash="abc",
            evidence_item={
                "check": "sanctions",
                "status": "approved",
                "provider_id": "http:sanctions",
                "reference": "case-1",
                "checked_at": 1,
                "details": {},
            },
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
    create_kyc_evidence_record(
        session=sqlite_session,
        bundle_hash="hash-1",
        check_type="kyc",
        provider_name="http:kyc",
        subject_id="rSubject",
        jurisdiction="US",
        kyc_status="verified",
        evidence_reference="case-1",
        checked_at=1700000000,
        evidence_payload={
            "status": "approved",
            "details": {"kyc_result": {"kyc_status": "verified"}},
        },
    )
    sqlite_session.commit()

    rows = get_kyc_evidence_by_bundle_hash(session=sqlite_session, bundle_hash="hash-1")
    assert len(rows) == 1
    row = rows[0]
    assert isinstance(row, KycEvidenceRecord)
    assert row.check_type == "kyc"
    assert row.provider_name == "http:kyc"
    assert row.subject_id == "rSubject"
    assert row.jurisdiction == "US"
    assert row.kyc_status == "verified"
    assert row.evidence_reference == "case-1"
    assert row.checked_at == 1700000000
    assert row.evidence_payload_json["details"]["kyc_result"]["kyc_status"] == "verified"
    assert row.id  # uuid generated


def test_save_kyc_evidence_persists_source_and_destination(sqlite_session):
    with patch.object(storage_service, "persistence_enabled", lambda: True):
        save_kyc_evidence(
            bundle_hash="hash-2",
            evidence_item={
                "check": "kyc",
                "status": "approved",
                "provider_id": "http:kyc",
                "reference": "kyc-src",
                "checked_at": 100,
                "details": {
                    "kyc_result": {
                        "provider_name": "http:kyc",
                        "subject_id": "rSrc",
                        "kyc_status": "verified",
                        "jurisdiction": "US",
                        "checked_at": 100,
                        "evidence_reference": "kyc-src",
                        "reason_codes": [],
                    }
                },
            },
            db=sqlite_session,
        )
        save_kyc_evidence(
            bundle_hash="hash-2",
            evidence_item={
                "check": "kyc:destination",
                "status": "denied",
                "provider_id": "http:kyc",
                "reference": "kyc-dst",
                "reason": "not_verified",
                "checked_at": 200,
                "details": {
                    "kyc_result": {
                        "provider_name": "http:kyc",
                        "subject_id": "rDst",
                        "kyc_status": "not_verified",
                        "jurisdiction": "US",
                        "checked_at": 200,
                        "evidence_reference": "kyc-dst",
                        "reason_codes": ["KYC_NOT_VERIFIED"],
                    }
                },
            },
            db=sqlite_session,
        )

    rows = get_kyc_evidence_by_bundle_hash(session=sqlite_session, bundle_hash="hash-2")
    assert len(rows) == 2
    by_check = {row.check_type: row for row in rows}
    assert by_check["kyc"].subject_id == "rSrc"
    assert by_check["kyc"].kyc_status == "verified"
    assert by_check["kyc:destination"].subject_id == "rDst"
    assert by_check["kyc:destination"].kyc_status == "not_verified"
    assert by_check["kyc:destination"].evidence_payload_json["reason"] == "not_verified"
