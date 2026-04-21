from __future__ import annotations

from pydantic import BaseModel, Field

from app.models.proof import ProofArtifact


class PermitRequest(BaseModel):
    subject: str = Field(..., description="Subject identifier (e.g. account address).")
    action: str = Field("transfer", description="Action to authorize ('transfer' or 'trustset').")
    amount: float | int | None = Field(None, description="Optional transfer amount.")
    counterparty: str | None = Field(None, description="Optional counterparty address.")


class PermitResponse(BaseModel):
    summary: dict
    bundle: dict
    signature: str
    signed_at: int
    expires_at: int
    expires_in_seconds: int
    bundle_hash: str
    validity: dict
    decision_result: str
    reason_codes: list[str]
    proof_artifact: ProofArtifact


class VerifyRequest(BaseModel):
    bundle: dict
    signature: str
