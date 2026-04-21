from __future__ import annotations

from sqlalchemy.orm import Session

from app.db.models import ProofArtifactRecord
from app.models.proof import ProofArtifact


def create_proof_artifact_record(
    *,
    session: Session,
    bundle_hash: str,
    artifact: ProofArtifact,
    artifact_type: str,
) -> ProofArtifactRecord:
    record = ProofArtifactRecord(
        bundle_hash=bundle_hash,
        entity_id=artifact.entity_id,
        module=artifact.module,
        artifact_type=artifact_type,
        decision_result=artifact.decision_result,
        rule_version_used=artifact.rule_version_used,
        evaluation_context_json=artifact.evaluation_context,
        reason_codes_json=artifact.reason_codes,
        timestamp=artifact.timestamp,
        anchor_metadata_json=artifact.anchor_metadata,
    )
    session.add(record)
    return record


def get_proof_artifact_by_entity_id(*, session: Session, entity_id: str) -> ProofArtifactRecord | None:
    return session.query(ProofArtifactRecord).filter(ProofArtifactRecord.entity_id == entity_id).first()
