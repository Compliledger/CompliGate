from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import settlement as settlement_routes
from app.api.routes import xrpl as xrpl_routes
from app.core import config
from app.models.proof import build_proof_artifact
from app.models.xrpl import SettlementVerifyByHashResponse

client = TestClient(app)
VALID_SUBJECT = "rN7n3473SaZBCG4dFL83w7PB5XDnEHyMQX"


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_public_key():
    response = client.get("/public-key")
    assert response.status_code == 200
    data = response.json()
    assert "public_key_b64" in data
    assert "public_key_hex" in data
    assert data["public_key_hex"].startswith("0x")


def test_permit():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    assert "bundle" in data
    assert "signature" in data
    assert "bundle_hash" in data


def test_verify_with_issued_permit():
    permit_resp = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert permit_resp.status_code == 200
    permit = permit_resp.json()

    verify_resp = client.post(
        "/v1/verify",
        json={"bundle": permit["bundle"], "signature": permit["signature"]},
    )
    assert verify_resp.status_code == 200
    data = verify_resp.json()
    assert data["signature_valid"] is True
    assert data["not_expired"] is True


def test_xrpl_health_without_live_network():
    expected = {
        "configured": True,
        "reachable": False,
        "network": "xrpl_testnet",
        "rlusd_configured": True,
        "demo_wallet_configured": False,
    }
    with patch.object(xrpl_routes, "get_xrpl_health_status", return_value=expected):
        response = client.get("/v1/xrpl/health")

    assert response.status_code == 200
    assert response.json() == expected


def test_xrpl_trustline_check_without_live_network():
    expected = {
        "address": VALID_SUBJECT,
        "trustline_exists": True,
        "issuer": "rIssuer",
        "currency": "RLUSD",
        "raw_lines_checked": 1,
    }
    with patch.object(xrpl_routes, "validate_trustline_check", return_value=expected) as mock_check:
        response = client.post("/v1/xrpl/trustline/check", json={"address": VALID_SUBJECT})

    assert response.status_code == 200
    assert response.json() == expected
    mock_check.assert_called_once_with(
        VALID_SUBJECT,
        config.RLUSD_ISSUER,
        config.RLUSD_CURRENCY,
        xrpl_routes.fetch_account_lines,
    )


def test_xrpl_payment_without_live_network():
    expected = {
        "submitted": True,
        "tx_hash": "MOCK_TX_HASH",
        "engine_result": "tesSUCCESS",
        "network": "xrpl_testnet",
        "currency": "RLUSD",
        "issuer": "rIssuer",
        "amount": "10",
        "destination": VALID_SUBJECT,
        "proof_link": {"bundle_hash": "bundle-hash-1", "tx_hash": "MOCK_TX_HASH"},
    }

    with patch.object(xrpl_routes, "enforce_destination_trustline") as mock_enforce, patch.object(
        xrpl_routes,
        "submit_xrpl_payment",
        return_value=expected,
    ) as mock_submit:
        response = client.post(
            "/v1/xrpl/payment",
            json={
                "destination": VALID_SUBJECT,
                "amount": "10",
                "memo_bundle_hash": "bundle-hash-1",
            },
        )

    assert response.status_code == 200
    assert response.json() == expected
    mock_enforce.assert_called_once()
    mock_submit.assert_called_once()


def test_settlement_verify_without_live_network():
    proof = build_proof_artifact(
        module="CompliGate",
        entity_id="MOCK_TX_HASH",
        rule_version_used=config.POLICY_VERSION,
        decision_result="SETTLED_COMPLIANT",
        evaluation_context={"bundle_hash": "bundle-hash-1", "tx_hash": "MOCK_TX_HASH"},
        reason_codes=["CURRENCY_MATCH"],
        timestamp=1700000000,
        bundle_hash="bundle-hash-1",
        anchor_metadata={"network": "xrpl_testnet", "tx_hash": "MOCK_TX_HASH", "verified_at": 1700000000},
    )
    expected = SettlementVerifyByHashResponse(
        decision_result="SETTLED_COMPLIANT",
        reason_codes=["CURRENCY_MATCH"],
        proof_artifact=proof,
    )

    with patch.object(
        settlement_routes,
        "verify_settlement_by_hash_service",
        return_value=expected,
    ) as mock_verify:
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": "bundle-hash-1", "tx_hash": "MOCK_TX_HASH"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "SETTLED_COMPLIANT"
    assert data["proof_artifact"]["bundle_hash"] == "bundle-hash-1"
    mock_verify.assert_called_once_with("bundle-hash-1", "MOCK_TX_HASH")


def test_settlement_verify_by_hash_not_found():
    response = client.post(
        "/v1/settlement/verify",
        json={"bundle_hash": "missing-bundle-hash", "tx_hash": "MOCK_TX_HASH"},
    )
    assert response.status_code == 404
    assert response.json() == {
        "detail": {
            "error": "permit_not_found",
            "reason": "No persisted permit context found for bundle_hash",
            "bundle_hash": "missing-bundle-hash",
        }
    }
