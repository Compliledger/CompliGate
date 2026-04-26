from __future__ import annotations

from typing import Any, Mapping

from sqlalchemy.orm import Session

from app.db.models import KycEvidenceRecord


def create_kyc_evidence_record(
    *,
    session: Session,
    bundle_hash: str,
    check_type: str,
    provider_name: str,
    subject_id: str,
    jurisdiction: str,
    kyc_status: str,
    evidence_reference: str | None,
    checked_at: int,
    evidence_payload: Mapping[str, Any],
) -> KycEvidenceRecord:
    record = KycEvidenceRecord(
        bundle_hash=bundle_hash,
        check_type=check_type or "kyc",
        provider_name=provider_name,
        subject_id=subject_id or "",
        jurisdiction=jurisdiction or "",
        kyc_status=kyc_status,
        evidence_reference=evidence_reference,
        checked_at=int(checked_at),
        evidence_payload_json=dict(evidence_payload),
    )
    session.add(record)
    return record


def get_kyc_evidence_by_bundle_hash(
    *, session: Session, bundle_hash: str
) -> list[KycEvidenceRecord]:
    return (
        session.query(KycEvidenceRecord)
        .filter(KycEvidenceRecord.bundle_hash == bundle_hash)
        .order_by(KycEvidenceRecord.checked_at.asc())
        .all()
    )
