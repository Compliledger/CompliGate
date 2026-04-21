from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db.session import get_engine, persistence_enabled
from app.models.permit import PermitResponse
from app.models.proof import ProofArtifact
from app.repositories.permit_repository import create_permit_record, get_permit_by_bundle_hash
from app.repositories.proof_artifact_repository import create_proof_artifact_record

logger = get_logger("main")


def _open_session() -> Session | None:
    engine = get_engine()
    if engine is None:
        return None
    return Session(bind=engine, future=True)


def save_permit(permit: PermitResponse, db: Session | None = None) -> None:
    if not persistence_enabled():
        return
    session = db or _open_session()
    if session is None:
        return
    should_close_session = db is None
    try:
        existing = get_permit_by_bundle_hash(session=session, bundle_hash=permit.bundle_hash)
        if existing is None:
            create_permit_record(session=session, permit=permit)
            try:
                session.commit()
            except Exception:
                session.rollback()
                logger.exception("Failed to persist permit record for bundle_hash=%s", permit.bundle_hash)
                raise
    finally:
        if should_close_session:
            session.close()


def save_proof_artifact(*, bundle_hash: str, artifact: ProofArtifact, artifact_type: str) -> None:
    if not persistence_enabled():
        return
    db = _open_session()
    if db is None:
        return
    try:
        create_proof_artifact_record(
            session=db,
            bundle_hash=bundle_hash,
            artifact=artifact,
            artifact_type=artifact_type,
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
        permit = get_permit_by_bundle_hash(session=db, bundle_hash=bundle_hash)
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
