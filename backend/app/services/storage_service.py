from __future__ import annotations

from sqlalchemy.orm import Session

from app.db.models import PermitRecord, ProofArtifactRecord
from app.db.session import get_engine, persistence_enabled
from app.models.permit import PermitResponse
from app.models.proof import ProofArtifact


def _open_session() -> Session | None:
    engine = get_engine()
    if engine is None:
        return None
    return Session(bind=engine, future=True)


def save_permit(permit: PermitResponse) -> None:
    if not persistence_enabled():
        return
    db = _open_session()
    if db is None:
        return
    try:
        existing = db.query(PermitRecord).filter(PermitRecord.bundle_hash == permit.bundle_hash).first()
        if existing is None:
            db.add(
                PermitRecord(
                    bundle_id=permit.bundle.get("bundle_id", ""),
                    bundle_hash=permit.bundle_hash,
                    subject=permit.bundle.get("subject", ""),
                    action=permit.bundle.get("action", ""),
                    policy_version=permit.bundle.get("policy_version", ""),
                    decision_result=permit.decision_result,
                    reason_codes=permit.reason_codes,
                    bundle_json=permit.bundle,
                    signature=permit.signature,
                    signed_at=permit.signed_at,
                    expires_at=permit.expires_at,
                    proof_artifact_json=(
                        permit.proof_artifact.model_dump() if permit.proof_artifact is not None else None
                    ),
                )
            )
            db.commit()
    finally:
        db.close()


def save_proof_artifact(*, bundle_hash: str, artifact: ProofArtifact, artifact_type: str) -> None:
    if not persistence_enabled():
        return
    db = _open_session()
    if db is None:
        return
    try:
        db.add(
            ProofArtifactRecord(
                bundle_hash=bundle_hash,
                entity_id=artifact.entity_id,
                module=artifact.module,
                artifact_type=artifact_type,
                decision_result=artifact.decision_result,
                rule_version_used=getattr(artifact, "rule_version_used", "") or "",
                evaluation_context_json=artifact.evaluation_context,
                reason_codes_json=artifact.reason_codes,
                timestamp=artifact.timestamp,
                anchor_metadata_json=artifact.anchor_metadata,
            )
        )
        db.commit()
    finally:
        db.close()


def get_permit_context(bundle_hash: str) -> dict | None:
    if not persistence_enabled():
        return None
    db = _open_session()
    if db is None:
        return None
    try:
        permit = db.query(PermitRecord).filter(PermitRecord.bundle_hash == bundle_hash).first()
        if permit is None:
            return None
        return {
            "bundle_hash": permit.bundle_hash,
            "bundle": permit.bundle_json,
            "proof_artifact": permit.proof_artifact_json,
            "issued_at": permit.signed_at,
        }
    finally:
        db.close()
