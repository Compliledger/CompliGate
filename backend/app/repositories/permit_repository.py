from __future__ import annotations

from sqlalchemy.orm import Session

from app.db.models import PermitRecord
from app.models.permit import PermitResponse


def _extract_policy_version(bundle: dict) -> str:
    policy = bundle.get("policy")
    if isinstance(policy, dict):
        version = policy.get("version")
        if isinstance(version, str):
            return version
    return ""


def create_permit_record(*, session: Session, permit: PermitResponse) -> PermitRecord:
    record = PermitRecord(
        bundle_id=permit.bundle.get("bundle_id", ""),
        bundle_hash=permit.bundle_hash,
        subject=permit.bundle.get("subject", ""),
        action=permit.bundle.get("action", ""),
        policy_version=_extract_policy_version(permit.bundle),
        decision_result=permit.decision_result,
        reason_codes=permit.reason_codes,
        bundle_json=permit.bundle,
        signature=permit.signature,
        signed_at=permit.signed_at,
        expires_at=permit.expires_at,
        proof_artifact_json=permit.proof_artifact.model_dump() if permit.proof_artifact is not None else None,
    )
    session.add(record)
    return record


def get_permit_by_bundle_hash(*, session: Session, bundle_hash: str) -> PermitRecord | None:
    return session.query(PermitRecord).filter(PermitRecord.bundle_hash == bundle_hash).first()
