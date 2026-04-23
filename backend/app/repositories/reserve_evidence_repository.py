from __future__ import annotations

from typing import Any, Mapping

from sqlalchemy.orm import Session

from app.db.models import ReserveEvidenceRecord


def create_reserve_evidence_record(
    *,
    session: Session,
    bundle_hash: str,
    provider_name: str,
    asset: str,
    issuer: str,
    attestation_reference: str | None,
    reserve_status: str,
    liquidity_status: str,
    checked_at: int,
    evidence_payload: Mapping[str, Any],
    signature_reference: str | None = None,
) -> ReserveEvidenceRecord:
    record = ReserveEvidenceRecord(
        bundle_hash=bundle_hash,
        provider_name=provider_name,
        asset=asset,
        issuer=issuer or "",
        attestation_reference=attestation_reference,
        reserve_status=reserve_status,
        liquidity_status=liquidity_status,
        checked_at=int(checked_at),
        evidence_payload_json=dict(evidence_payload),
        signature_reference=signature_reference,
    )
    session.add(record)
    return record


def get_reserve_evidence_by_bundle_hash(
    *, session: Session, bundle_hash: str
) -> list[ReserveEvidenceRecord]:
    return (
        session.query(ReserveEvidenceRecord)
        .filter(ReserveEvidenceRecord.bundle_hash == bundle_hash)
        .order_by(ReserveEvidenceRecord.checked_at.asc())
        .all()
    )
