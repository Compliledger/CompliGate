from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest

from app.models.compliproof import (
    ARTIFACT_TYPE,
    SCHEMA_VERSION,
    CompliProof,
    Evidence,
    FinalDecision,
    ModuleDecision,
    ModuleDecisionResult,
    Subject,
)
from app.services.compliproof_service import (
    determine_final_decision,
    generate_compliproof,
)


def _subject() -> Subject:
    return Subject(
        asset_id="asset-1",
        issuer_id="issuer-1",
        transaction_id="tx-1",
    )


def _evidence() -> Evidence:
    return Evidence(
        reserve_ratio=1.02,
        liquidity_ratio=0.35,
        sanctions_status="clear",
        classification="regulated_stablecoin",
        permit_id="permit-123",
        settlement_attestation_id="settle-456",
    )


@pytest.mark.parametrize(
    "decisions, expected",
    [
        ([ModuleDecisionResult.PASS, ModuleDecisionResult.PASS], FinalDecision.COMPLIANT),
        ([ModuleDecisionResult.PASS, ModuleDecisionResult.CONDITIONAL], FinalDecision.CONDITIONAL),
        (
            [ModuleDecisionResult.CONDITIONAL, ModuleDecisionResult.FAIL],
            FinalDecision.NON_COMPLIANT,
        ),
        ([ModuleDecisionResult.FAIL], FinalDecision.NON_COMPLIANT),
        ([], FinalDecision.COMPLIANT),
    ],
)
def test_determine_final_decision(decisions, expected):
    mds = [
        ModuleDecision(module=f"m{i}", decision=d) for i, d in enumerate(decisions)
    ]
    assert determine_final_decision(mds) == expected


def test_generate_compliproof_compliant_collects_reason_codes_and_versions():
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    completed = datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc)
    proof = generate_compliproof(
        subject=_subject(),
        module_decisions=[
            ModuleDecision(
                module="kyc",
                decision=ModuleDecisionResult.PASS,
                reason_codes=["KYC_OK"],
                rule_version="kyc-1.0",
            ),
            ModuleDecision(
                module="reserve",
                decision=ModuleDecisionResult.PASS,
                reason_codes=["RESERVE_OK"],
                rule_version="reserve-2.1",
            ),
        ],
        evidence=_evidence(),
        started_at=started,
        completed_at=completed,
    )

    assert isinstance(proof, CompliProof)
    assert proof.artifact_type == ARTIFACT_TYPE
    assert proof.schema_version == SCHEMA_VERSION
    assert isinstance(proof.artifact_id, UUID)
    assert proof.final_decision == FinalDecision.COMPLIANT
    assert proof.reason_codes == ["KYC_OK", "RESERVE_OK"]
    assert proof.rule_versions == ["kyc-1.0", "reserve-2.1"]
    assert proof.lifecycle.stages_completed == ["kyc", "reserve"]
    assert proof.lifecycle.started_at == started
    assert proof.lifecycle.completed_at == completed
    assert proof.hashes.canonical_hash
    assert proof.hashes.bundle_hash == proof.hashes.canonical_hash
    assert proof.anchor is None


def test_generate_compliproof_fail_overrides_conditional():
    proof = generate_compliproof(
        subject=_subject(),
        module_decisions=[
            ModuleDecision(
                module="kyc",
                decision=ModuleDecisionResult.CONDITIONAL,
                reason_codes=["KYC_REVIEW"],
            ),
            ModuleDecision(
                module="sanctions",
                decision=ModuleDecisionResult.FAIL,
                reason_codes=["SANCTIONS_HIT"],
            ),
        ],
        evidence=_evidence(),
    )
    assert proof.final_decision == FinalDecision.NON_COMPLIANT
    assert proof.reason_codes == ["KYC_REVIEW", "SANCTIONS_HIT"]


def test_generate_compliproof_conditional_when_no_fail():
    proof = generate_compliproof(
        subject=_subject(),
        module_decisions=[
            ModuleDecision(module="kyc", decision=ModuleDecisionResult.PASS),
            ModuleDecision(
                module="reserve",
                decision=ModuleDecisionResult.CONDITIONAL,
                reason_codes=["RESERVE_LOW"],
            ),
        ],
        evidence=_evidence(),
    )
    assert proof.final_decision == FinalDecision.CONDITIONAL


def test_generate_compliproof_canonical_hash_is_deterministic():
    common = dict(
        subject=_subject(),
        module_decisions=[
            ModuleDecision(
                module="kyc",
                decision=ModuleDecisionResult.PASS,
                reason_codes=["KYC_OK"],
                rule_version="kyc-1.0",
            ),
        ],
        evidence=_evidence(),
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        completed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        artifact_id=UUID("12345678-1234-5678-1234-567812345678"),
    )
    a = generate_compliproof(**common)
    b = generate_compliproof(**common)
    assert a.hashes.canonical_hash == b.hashes.canonical_hash


def test_generate_compliproof_accepts_dict_inputs():
    proof = generate_compliproof(
        subject={
            "asset_id": "asset-1",
            "issuer_id": "issuer-1",
            "transaction_id": "tx-1",
        },
        module_decisions=[
            {"module": "kyc", "decision": "PASS", "reason_codes": []},
        ],
        evidence={"reserve_ratio": 1.0},
    )
    assert proof.final_decision == FinalDecision.COMPLIANT
    assert proof.evidence.reserve_ratio == 1.0


def test_reason_codes_are_deduplicated_preserving_order():
    proof = generate_compliproof(
        subject=_subject(),
        module_decisions=[
            ModuleDecision(
                module="m1",
                decision=ModuleDecisionResult.PASS,
                reason_codes=["A", "B"],
            ),
            ModuleDecision(
                module="m2",
                decision=ModuleDecisionResult.PASS,
                reason_codes=["B", "C"],
            ),
        ],
        evidence=_evidence(),
    )
    assert proof.reason_codes == ["A", "B", "C"]
