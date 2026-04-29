"""Orchestrator for the demo lifecycle.

Runs the eight thin-MVP CompliStack services in the prescribed order
against fixture data for the requested scenario, assembles the
universal CompliProof artifact, and produces a (synthetic) Algorand
anchor plus a verification URL.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Final

from app.models.compliproof import (
    Anchor,
    Evidence,
    FinalDecision,
    ModuleDecision,
    ModuleDecisionResult,
    Subject,
)
from app.services.compliproof_service import generate_compliproof
from app.services.lifecycle.demo_fixtures import SCENARIOS, get_fixture
from app.services.lifecycle.modules import (
    AlgorandAdapter,
    CompliGate,
    CompliGuard,
    MarketProof,
    SettlementGuard,
    SolvencyProof,
    TokenProof,
)

SUPPORTED_SCENARIOS: Final[tuple[str, ...]] = SCENARIOS


# Lifecycle status string returned to API clients. Mirrors the rolled-up
# CompliProof final decision but uses lifecycle-oriented language so it
# is unambiguous in demo dashboards.
_LIFECYCLE_STATUS_BY_DECISION: Final[dict[FinalDecision, str]] = {
    FinalDecision.COMPLIANT: "COMPLETED_COMPLIANT",
    FinalDecision.CONDITIONAL: "COMPLETED_WITH_CONDITIONS",
    FinalDecision.NON_COMPLIANT: "HALTED_NON_COMPLIANT",
}


def _build_evidence(
    fixture: dict, decisions: list[ModuleDecision]
) -> Evidence:
    """Aggregate evidence fields from the fixture + decisions for the proof."""
    sanctions_status = (
        "hit" if fixture["transaction"].get("sanctions_hit") else "clear"
    )
    classification = fixture["token"].get("intended_classification")
    settlement_attestation_id = fixture["settlement"].get("settlement_id")
    return Evidence(
        reserve_ratio=fixture["reserves"].get("reserve_ratio"),
        liquidity_ratio=fixture["reserves"].get("liquidity_ratio"),
        sanctions_status=sanctions_status,
        classification=classification,
        permit_id=None,
        settlement_attestation_id=settlement_attestation_id,
    )


def run_demo_lifecycle(scenario: str) -> dict:
    """Run the full thin-MVP lifecycle for ``scenario``.

    Args:
        scenario: One of :data:`SUPPORTED_SCENARIOS`.

    Returns:
        A dict with the demo lifecycle result. Keys mirror the API
        response: ``scenario``, ``lifecycle_status``,
        ``module_decisions``, ``compliproof_artifact``, ``proof_hash``,
        ``algorand_anchor``, and ``verification_url``.

    Raises:
        KeyError: when ``scenario`` is unknown.
    """
    fixture = get_fixture(scenario)

    started_at = datetime.now(timezone.utc)

    # 1. MarketProof.validate_issuer
    market_decision = MarketProof.validate_issuer(fixture["issuer"])
    # 2. TokenProof.classify_token
    token_decision = TokenProof.classify_token(fixture["token"])
    # 3. SolvencyProof.check_reserves_and_liquidity
    solvency_decision = SolvencyProof.check_reserves_and_liquidity(
        fixture["reserves"]
    )
    # 4. CompliGate.authorize_transaction
    compligate_decision = CompliGate.authorize_transaction(fixture["transaction"])
    # 5. CompliGuard.monitor_risk
    compliguard_decision = CompliGuard.monitor_risk(fixture["risk_signals"])
    # 6. SettlementGuard.validate_settlement (must respect upstream gate)
    gate_passed = compligate_decision.decision != ModuleDecisionResult.FAIL
    settlement_decision = SettlementGuard.validate_settlement(
        fixture["settlement"], gate_passed=gate_passed
    )

    decisions: list[ModuleDecision] = [
        market_decision,
        token_decision,
        solvency_decision,
        compligate_decision,
        compliguard_decision,
        settlement_decision,
    ]

    completed_at = datetime.now(timezone.utc)

    # 7. CompliProofService.generate_compliproof
    subject = Subject(**fixture["subject"])
    evidence = _build_evidence(fixture, decisions)
    compliproof = generate_compliproof(
        subject=subject,
        module_decisions=decisions,
        evidence=evidence,
        started_at=started_at,
        completed_at=completed_at,
    )

    # 8. AlgorandAdapter.anchor_proof
    anchored_at = datetime.now(timezone.utc)
    anchor_dict = AlgorandAdapter.anchor_proof(
        compliproof.hashes.canonical_hash, anchored_at=anchored_at
    )
    compliproof.anchor = Anchor(**anchor_dict)

    lifecycle_status = _LIFECYCLE_STATUS_BY_DECISION[compliproof.final_decision]
    verification_url = anchor_dict["explorer_url"]

    return {
        "scenario": scenario,
        "lifecycle_status": lifecycle_status,
        "module_decisions": [md.model_dump(mode="json") for md in decisions],
        "compliproof_artifact": compliproof.model_dump(mode="json"),
        "proof_hash": compliproof.hashes.canonical_hash,
        "algorand_anchor": {
            **anchor_dict,
            "anchored_at": anchored_at.isoformat(),
        },
        "verification_url": verification_url,
    }
