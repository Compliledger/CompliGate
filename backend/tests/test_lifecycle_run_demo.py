from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.compliproof import ARTIFACT_TYPE
from app.services.lifecycle import run_demo_lifecycle
from app.services.lifecycle.demo_fixtures import SCENARIOS

client = TestClient(app)


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_run_demo_lifecycle_returns_expected_keys(scenario):
    result = run_demo_lifecycle(scenario)

    expected_keys = {
        "scenario",
        "lifecycle_status",
        "module_decisions",
        "compliproof_artifact",
        "proof_hash",
        "algorand_anchor",
        "verification_url",
    }
    assert expected_keys.issubset(result.keys())
    assert result["scenario"] == scenario

    # Every lifecycle run must include all 6 module decisions in the
    # prescribed order; the 7th (CompliProofService) is reflected as the
    # artifact itself, and the 8th (AlgorandAdapter) as the anchor.
    modules_in_order = [md["module"] for md in result["module_decisions"]]
    assert modules_in_order == [
        "MarketProof",
        "TokenProof",
        "SolvencyProof",
        "CompliGate",
        "CompliGuard",
        "SettlementGuard",
    ]

    artifact = result["compliproof_artifact"]
    assert artifact["artifact_type"] == ARTIFACT_TYPE
    assert artifact["hashes"]["canonical_hash"] == result["proof_hash"]
    assert artifact["anchor"]["tx_id"] == result["algorand_anchor"]["tx_id"]

    anchor = result["algorand_anchor"]
    assert anchor["chain"] == "algorand"
    assert anchor["network"] == "algorand_testnet"
    assert anchor["tx_id"].startswith("DEMO")
    assert result["verification_url"] == anchor["explorer_url"]


def test_fully_compliant_scenario_is_compliant():
    result = run_demo_lifecycle("fully_compliant")
    assert result["lifecycle_status"] == "COMPLETED_COMPLIANT"
    assert result["compliproof_artifact"]["final_decision"] == "COMPLIANT"
    decisions = {md["module"]: md["decision"] for md in result["module_decisions"]}
    assert all(d == "PASS" for d in decisions.values())


def test_liquidity_risk_scenario_is_conditional():
    result = run_demo_lifecycle("liquidity_risk")
    assert result["lifecycle_status"] == "COMPLETED_WITH_CONDITIONS"
    assert result["compliproof_artifact"]["final_decision"] == "CONDITIONAL"
    decisions = {md["module"]: md["decision"] for md in result["module_decisions"]}
    assert decisions["SolvencyProof"] == "CONDITIONAL"
    # No module should hard-fail in this scenario.
    assert "FAIL" not in decisions.values()
    assert "LIQUIDITY_BUFFER_LOW" in result["compliproof_artifact"]["reason_codes"]


def test_sanctions_hit_scenario_halts_lifecycle():
    result = run_demo_lifecycle("sanctions_hit")
    assert result["lifecycle_status"] == "HALTED_NON_COMPLIANT"
    assert result["compliproof_artifact"]["final_decision"] == "NON_COMPLIANT"
    decisions = {md["module"]: md["decision"] for md in result["module_decisions"]}
    assert decisions["CompliGate"] == "FAIL"
    # SettlementGuard must respect the upstream gate failure.
    assert decisions["SettlementGuard"] == "FAIL"
    assert "SANCTIONS_HIT" in result["compliproof_artifact"]["reason_codes"]


def test_reserve_shortfall_scenario_halts_lifecycle():
    result = run_demo_lifecycle("reserve_shortfall")
    assert result["lifecycle_status"] == "HALTED_NON_COMPLIANT"
    assert result["compliproof_artifact"]["final_decision"] == "NON_COMPLIANT"
    decisions = {md["module"]: md["decision"] for md in result["module_decisions"]}
    assert decisions["SolvencyProof"] == "FAIL"
    assert "RESERVE_SHORTFALL" in result["compliproof_artifact"]["reason_codes"]


def test_run_demo_endpoint_returns_200_for_each_scenario():
    for scenario in SCENARIOS:
        response = client.post(
            "/lifecycle/run-demo", json={"scenario": scenario}
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["scenario"] == scenario
        assert body["proof_hash"]
        assert body["compliproof_artifact"]["hashes"]["canonical_hash"] == body["proof_hash"]


def test_run_demo_endpoint_rejects_unknown_scenario():
    response = client.post(
        "/lifecycle/run-demo", json={"scenario": "not_a_real_scenario"}
    )
    assert response.status_code == 422


def test_run_demo_endpoint_rejects_missing_scenario():
    response = client.post("/lifecycle/run-demo", json={})
    assert response.status_code == 422
