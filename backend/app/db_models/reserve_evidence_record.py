from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import JSON, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base

JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


class ReserveEvidenceRecord(Base):
    """Structured reserve / liquidity evidence linked to a proof artifact.

    Each row captures the *real* attestation a configured reserve provider
    returned for a permit decision, so auditors can answer "what evidence
    backed this permit's reserve / liquidity claim?" without parsing the
    bundle JSON. The ``bundle_hash`` column links the row to the
    corresponding entry in ``proof_artifacts`` / ``permits``.

    Notes:

    * ``attestation_reference`` is the provider-supplied reference (URL,
      attestation id, case id, ...). It is never a random hash – when the
      provider did not return one the column is ``NULL`` so the record
      never claims an attestation that does not exist.
    * ``reserve_status`` and ``liquidity_status`` are the normalized
      provider statuses (``approved`` / ``denied`` / ``unavailable``);
      they are derived from the provider response and are never
      hard-coded to a positive value.
    """

    __tablename__ = "reserve_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    bundle_hash: Mapped[str] = mapped_column(String(64), index=True)
    provider_name: Mapped[str] = mapped_column(String(128), index=True)
    asset: Mapped[str] = mapped_column(String(64), index=True)
    issuer: Mapped[str] = mapped_column(String(128), default="", index=True)
    attestation_reference: Mapped[str | None] = mapped_column(String(512), nullable=True)
    reserve_status: Mapped[str] = mapped_column(String(32), index=True)
    liquidity_status: Mapped[str] = mapped_column(String(32), index=True)
    checked_at: Mapped[int] = mapped_column(Integer, index=True)
    evidence_payload_json: Mapped[dict] = mapped_column(JSON_TYPE)
    signature_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
