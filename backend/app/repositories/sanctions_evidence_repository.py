from __future__ import annotations

from typing import Any, Mapping

from sqlalchemy.orm import Session

from app.db.models import SanctionsEvidenceRecord


def create_sanctions_evidence_record(
    *,
    session: Session,
    bundle_hash: str,
    provider_name: str,
    subject: str,
    jurisdiction: str,
    sanctions_status: str,
    evidence_reference: str | None,
    checked_at: int,
    evidence_payload: Mapping[str, Any],
) -> SanctionsEvidenceRecord:
    record = SanctionsEvidenceRecord(
        bundle_hash=bundle_hash,
        provider_name=provider_name,
        subject=subject or "",
        jurisdiction=jurisdiction or "",
        sanctions_status=sanctions_status,
        evidence_reference=evidence_reference,
        checked_at=int(checked_at),
        evidence_payload_json=dict(evidence_payload),
    )
    session.add(record)
    return record


def get_sanctions_evidence_by_bundle_hash(
    *, session: Session, bundle_hash: str
) -> list[SanctionsEvidenceRecord]:
    return (
        session.query(SanctionsEvidenceRecord)
        .filter(SanctionsEvidenceRecord.bundle_hash == bundle_hash)
        .order_by(SanctionsEvidenceRecord.checked_at.asc())
        .all()
    )
