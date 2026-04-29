"""Pydantic schema for the universal CompliProof artifact.

The CompliProof artifact is the lifecycle-level proof produced by the
CompliStack MVP. It aggregates the per-module decisions emitted by the
individual compliance modules (KYC, sanctions, reserve, settlement,
permit, ...) into a single auditable artifact that can be canonically
hashed and (optionally) anchored on-chain.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

ARTIFACT_TYPE = "COMPLISTACK_LIFECYCLE_PROOF"
SCHEMA_VERSION = "1.0.0"


class FinalDecision(str, Enum):
    """Aggregate decision for the CompliStack lifecycle."""

    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    CONDITIONAL = "CONDITIONAL"


class ModuleDecisionResult(str, Enum):
    """Per-module decision result."""

    PASS = "PASS"
    FAIL = "FAIL"
    CONDITIONAL = "CONDITIONAL"


class Subject(BaseModel):
    """Identifies the asset / issuer / transaction the proof covers."""

    asset_id: str
    issuer_id: str
    transaction_id: str


class Lifecycle(BaseModel):
    """Lifecycle metadata describing the stages that ran."""

    stages_completed: list[str] = Field(default_factory=list)
    started_at: datetime
    completed_at: datetime


class ModuleDecision(BaseModel):
    """Decision emitted by an individual compliance module."""

    module: str
    decision: ModuleDecisionResult
    reason_codes: list[str] = Field(default_factory=list)
    rule_version: str | None = None
    evidence_reference: str | None = None


class Evidence(BaseModel):
    """Aggregated evidence fields from all modules.

    Fields are optional because not every lifecycle exercises every
    module. Only the values that were actually produced should be set.
    """

    reserve_ratio: float | None = None
    liquidity_ratio: float | None = None
    sanctions_status: str | None = None
    classification: str | None = None
    permit_id: str | None = None
    settlement_attestation_id: str | None = None


class Hashes(BaseModel):
    """Canonical and bundle hashes of the artifact."""

    canonical_hash: str
    bundle_hash: str | None = None


class Anchor(BaseModel):
    """On-chain anchor metadata. Optional until the artifact is anchored."""

    chain: str | None = None
    network: str | None = None
    tx_id: str | None = None
    explorer_url: str | None = None
    anchored_at: datetime | None = None


class CompliProof(BaseModel):
    """Universal CompliProof artifact for the CompliStack MVP."""

    artifact_id: UUID
    artifact_type: Literal["COMPLISTACK_LIFECYCLE_PROOF"] = ARTIFACT_TYPE
    schema_version: Literal["1.0.0"] = SCHEMA_VERSION
    subject: Subject
    lifecycle: Lifecycle
    final_decision: FinalDecision
    module_decisions: list[ModuleDecision] = Field(default_factory=list)
    rule_versions: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    evidence: Evidence
    hashes: Hashes
    anchor: Anchor | None = None
