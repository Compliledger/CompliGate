from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import JSON, DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base

JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


class SanctionsEvidenceRecord(Base):
    """Structured sanctions screening evidence linked to a proof artifact.

    Each row captures the *real* attestation a configured sanctions
    screening provider returned for a permit decision so auditors can
    answer "what evidence backed this permit's sanctions claim?"
    without parsing the bundle JSON. The ``bundle_hash`` column links
    the row to the corresponding entry in ``proof_artifacts`` and
    ``permits`` (proof artifacts and permits share the same
    ``bundle_hash`` so a single column links to both).

    Notes:

    * ``evidence_reference`` is the provider-supplied reference (case
      id, screening id, URL, ...). It is never a synthetic random
      value -- when the provider did not return one the column is
      ``NULL`` so the record never claims an attestation that does
      not exist.
    * ``sanctions_status`` is the normalized provider outcome
      (``approved`` / ``denied`` / ``unavailable``); it is derived
      from the provider response and is never hard-coded to a
      positive value.
    * ``evidence_payload_json`` carries the engine-normalized metadata
      (``check``, normalized ``status``, ``reason``, optional bounded
      raw response excerpt). Provider credentials, API keys and other
      secrets are intentionally never written here -- providers are
      responsible for keeping them out of their evidence ``details``
      and the storage layer treats the payload as already-sanitized
      normalized metadata.
    """

    __tablename__ = "sanctions_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    bundle_hash: Mapped[str] = mapped_column(String(64), index=True)
    provider_name: Mapped[str] = mapped_column(String(128), index=True)
    subject: Mapped[str] = mapped_column(String(128), default="", index=True)
    jurisdiction: Mapped[str] = mapped_column(String(32), default="", index=True)
    sanctions_status: Mapped[str] = mapped_column(String(32), index=True)
    evidence_reference: Mapped[str | None] = mapped_column(String(512), nullable=True)
    checked_at: Mapped[int] = mapped_column(Integer, index=True)
    evidence_payload_json: Mapped[dict] = mapped_column(JSON_TYPE)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
