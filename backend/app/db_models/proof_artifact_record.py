from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import JSON, DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base

JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


class ProofArtifactRecord(Base):
    __tablename__ = "proof_artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    entity_id: Mapped[str] = mapped_column(String(128), index=True)
    module: Mapped[str] = mapped_column(String(64), index=True)
    bundle_hash: Mapped[str] = mapped_column(String(64), index=True)
    artifact_type: Mapped[str] = mapped_column(String(32), index=True)
    decision_result: Mapped[str] = mapped_column(String(64), index=True)
    rule_version_used: Mapped[str] = mapped_column(String(128), default="")
    evaluation_context_json: Mapped[dict] = mapped_column(JSON_TYPE)
    reason_codes_json: Mapped[list[str]] = mapped_column(JSON_TYPE)
    timestamp: Mapped[int] = mapped_column(Integer, index=True)
    anchor_metadata_json: Mapped[dict] = mapped_column(JSON_TYPE)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
