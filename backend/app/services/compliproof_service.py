"""Service for generating universal CompliProof lifecycle artifacts.

The CompliProof artifact aggregates per-module decisions produced by
the various CompliStack modules into a single auditable artifact with
a canonical hash. It is intentionally independent of any particular
module so it can serve as the universal lifecycle proof for the MVP.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from app.models.compliproof import (
    ARTIFACT_TYPE,
    SCHEMA_VERSION,
    Anchor,
    CompliProof,
    Evidence,
    FinalDecision,
    Hashes,
    Lifecycle,
    ModuleDecision,
    ModuleDecisionResult,
    Subject,
)
from app.utils.hashing import proof_hash


def _coerce_subject(subject: Subject | dict) -> Subject:
    return subject if isinstance(subject, Subject) else Subject(**subject)


def _coerce_evidence(evidence: Evidence | dict | None) -> Evidence:
    if evidence is None:
        return Evidence()
    return evidence if isinstance(evidence, Evidence) else Evidence(**evidence)


def _coerce_module_decisions(
    module_decisions: list[ModuleDecision | dict],
) -> list[ModuleDecision]:
    coerced: list[ModuleDecision] = []
    for md in module_decisions:
        coerced.append(md if isinstance(md, ModuleDecision) else ModuleDecision(**md))
    return coerced


def determine_final_decision(
    module_decisions: list[ModuleDecision],
) -> FinalDecision:
    """Roll up per-module decisions into a single lifecycle decision.

    Rules:
        * NON_COMPLIANT if any module decision is FAIL.
        * CONDITIONAL if any module decision is CONDITIONAL and no FAIL.
        * COMPLIANT otherwise (all PASS or empty).
    """
    has_fail = any(md.decision == ModuleDecisionResult.FAIL for md in module_decisions)
    if has_fail:
        return FinalDecision.NON_COMPLIANT
    has_conditional = any(
        md.decision == ModuleDecisionResult.CONDITIONAL for md in module_decisions
    )
    if has_conditional:
        return FinalDecision.CONDITIONAL
    return FinalDecision.COMPLIANT


def _collect_reason_codes(module_decisions: list[ModuleDecision]) -> list[str]:
    """Concatenate reason codes from every module decision in order, de-duplicated."""
    seen: set[str] = set()
    ordered: list[str] = []
    for md in module_decisions:
        for code in md.reason_codes:
            if code not in seen:
                seen.add(code)
                ordered.append(code)
    return ordered


def _collect_rule_versions(module_decisions: list[ModuleDecision]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for md in module_decisions:
        if md.rule_version and md.rule_version not in seen:
            seen.add(md.rule_version)
            ordered.append(md.rule_version)
    return ordered


def _build_canonical_payload(
    *,
    artifact_id: UUID,
    subject: Subject,
    lifecycle: Lifecycle,
    final_decision: FinalDecision,
    module_decisions: list[ModuleDecision],
    rule_versions: list[str],
    reason_codes: list[str],
    evidence: Evidence,
) -> dict:
    """Build the dict that the canonical hash is computed over.

    The hash deliberately excludes the ``hashes`` and ``anchor`` blocks
    so that anchoring an artifact does not change its canonical hash.
    """
    return {
        "artifact_id": str(artifact_id),
        "artifact_type": ARTIFACT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "subject": subject.model_dump(mode="json"),
        "lifecycle": lifecycle.model_dump(mode="json"),
        "final_decision": final_decision.value,
        "module_decisions": [md.model_dump(mode="json") for md in module_decisions],
        "rule_versions": rule_versions,
        "reason_codes": reason_codes,
        "evidence": evidence.model_dump(mode="json"),
    }


def generate_compliproof(
    subject: Subject | dict,
    module_decisions: list[ModuleDecision | dict],
    evidence: Evidence | dict | None = None,
    *,
    stages_completed: list[str] | None = None,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    rule_versions: list[str] | None = None,
    anchor: Anchor | dict | None = None,
    artifact_id: UUID | None = None,
) -> CompliProof:
    """Generate a CompliProof artifact from per-module decisions.

    Args:
        subject: Identifies the asset/issuer/transaction the proof covers.
        module_decisions: Decisions produced by each compliance module.
        evidence: Aggregated evidence fields gathered during the lifecycle.
        stages_completed: Names of lifecycle stages that ran. Defaults
            to the module names from ``module_decisions``.
        started_at / completed_at: Lifecycle timestamps. Default to ``now``.
        rule_versions: Optional explicit rule versions. When omitted,
            the unique rule versions referenced by the module decisions
            are used.
        anchor: Optional on-chain anchor metadata if already known.
        artifact_id: Optional explicit artifact id (mainly for tests /
            replay). A new UUIDv4 is generated when omitted.
    """
    subject_obj = _coerce_subject(subject)
    evidence_obj = _coerce_evidence(evidence)
    decisions = _coerce_module_decisions(module_decisions)

    final_decision = determine_final_decision(decisions)
    reason_codes = _collect_reason_codes(decisions)
    versions = (
        list(rule_versions)
        if rule_versions is not None
        else _collect_rule_versions(decisions)
    )

    now = datetime.now(timezone.utc)
    lifecycle = Lifecycle(
        stages_completed=(
            list(stages_completed)
            if stages_completed is not None
            else [md.module for md in decisions]
        ),
        started_at=started_at or now,
        completed_at=completed_at or now,
    )

    artifact_uuid = artifact_id or uuid4()

    canonical_payload = _build_canonical_payload(
        artifact_id=artifact_uuid,
        subject=subject_obj,
        lifecycle=lifecycle,
        final_decision=final_decision,
        module_decisions=decisions,
        rule_versions=versions,
        reason_codes=reason_codes,
        evidence=evidence_obj,
    )
    canonical_hash = proof_hash(canonical_payload)

    anchor_obj: Anchor | None
    if anchor is None:
        anchor_obj = None
    elif isinstance(anchor, Anchor):
        anchor_obj = anchor
    else:
        anchor_obj = Anchor(**anchor)

    return CompliProof(
        artifact_id=artifact_uuid,
        artifact_type=ARTIFACT_TYPE,
        schema_version=SCHEMA_VERSION,
        subject=subject_obj,
        lifecycle=lifecycle,
        final_decision=final_decision,
        module_decisions=decisions,
        rule_versions=versions,
        reason_codes=reason_codes,
        evidence=evidence_obj,
        hashes=Hashes(canonical_hash=canonical_hash, bundle_hash=canonical_hash),
        anchor=anchor_obj,
    )
