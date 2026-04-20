import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException
from unittest.mock import patch, MagicMock
import logging
from main import app, evaluate_governance, evaluate_eligibility, evaluate_constraints, verify_settlement_against_permit, _evaluate_settlement_constraints, check_rlusd_trustline, validate_trustline, build_proof_link

client = TestClient(app)

VALID_SUBJECT = "rN7n3473SaZBCG4dFL83w7PB5XDnEHyMQX"


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_permit_returns_bundle_signature_hash():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    assert "bundle" in data
    assert "signature" in data
    assert "bundle_hash" in data


def test_permit_validity_field():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    assert "validity" in data
    assert data["validity"] == {"single_use": False}


def test_permit_default_action_is_transfer():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    bundle = data["bundle"]
    assert bundle["action"] == "transfer"
    assert bundle["scope"] == ["transfer"]


def test_permit_custom_action():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "action": "trustset"})
    assert response.status_code == 200
    data = response.json()
    bundle = data["bundle"]
    assert bundle["action"] == "trustset"
    assert bundle["scope"] == ["trustset"]


def test_permit_unsupported_action_returns_400():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "action": "payment"})
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "unsupported_action"
    assert "reason" in detail


def test_permit_amount_exceeds_max_returns_400():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "amount": 5000001})
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "transaction_not_allowed"
    assert detail["reason"] == "amount exceeds policy maximum"


def test_permit_amount_at_max_is_allowed():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "amount": 5000000})
    assert response.status_code == 200


def test_permit_counterparty_in_constraints():
    counterparty = "rCounterparty1234567890123456789"
    response = client.post(
        "/v1/permit",
        json={"subject": VALID_SUBJECT, "counterparty": counterparty},
    )
    assert response.status_code == 200
    bundle = response.json()["bundle"]
    assert bundle["constraints"]["allowed_counterparty"] == counterparty


def test_permit_with_amount():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "amount": 500.0})
    assert response.status_code == 200
    data = response.json()
    assert "bundle" in data
    assert "signature" in data
    assert "bundle_hash" in data


def test_permit_bundle_structure():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    bundle = response.json()["bundle"]
    assert bundle["subject"] == VALID_SUBJECT
    assert "bundle_id" in bundle
    assert "nonce" in bundle
    assert "exp" in bundle
    assert "policy_id" in bundle["asset"]
    assert bundle["asset"]["classification"] == "regulated_stablecoin"
    assert "max_amount" in bundle["constraints"]
    assert bundle["constraints"]["allowed_counterparty"] is None
    assert "attestations" in bundle
    assert "custody_hash" in bundle["attestations"]
    assert "reserve_hash" in bundle["attestations"]


def test_permit_subject_validation_no_r():
    response = client.post("/v1/permit", json={"subject": "xInvalidAddress12345678901234"})
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "invalid_subject"
    assert "r" in detail["reason"]


def test_permit_subject_validation_too_short():
    response = client.post("/v1/permit", json={"subject": "rShort"})
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "invalid_subject"
    assert "25-35" in detail["reason"]


def test_permit_subject_validation_too_long():
    response = client.post("/v1/permit", json={"subject": "r" + "a" * 35})
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "invalid_subject"
    assert "25-35" in detail["reason"]


def test_verify_validates_signature():
    permit_response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert permit_response.status_code == 200
    permit = permit_response.json()

    verify_response = client.post(
        "/v1/verify",
        json={"bundle": permit["bundle"], "signature": permit["signature"]},
    )
    assert verify_response.status_code == 200
    data = verify_response.json()
    assert data["signature_valid"] is True
    assert data["not_expired"] is True


SAMPLE_TX_HASH = "ABC123DEF456789012345678901234567890123456789012345678901234"


def _get_valid_permit():
    """Issue a permit and return the response data."""
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "amount": 500})
    assert response.status_code == 200
    return response.json()


def _make_xrpl_payment_tx(account, destination, currency, value, validated=True):
    """Build a mock XRPL Payment transaction result."""
    return {
        "Account": account,
        "Destination": destination,
        "TransactionType": "Payment",
        "Amount": {"currency": currency, "value": str(value), "issuer": "rISSUER"},
        "validated": validated,
    }


def _make_xrpl_trustset_tx(account, currency, validated=True):
    """Build a mock XRPL TrustSet transaction result."""
    return {
        "Account": account,
        "TransactionType": "TrustSet",
        "LimitAmount": {"currency": currency, "value": "1000000", "issuer": "rISSUER"},
        "validated": validated,
    }


def test_settle_verify_valid_payment():
    permit = _get_valid_permit()
    tx_data = _make_xrpl_payment_tx(
        account=VALID_SUBJECT,
        destination="rCounterparty1234567890123456789",
        currency="RLUSD",
        value=500,
    )

    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settle/verify",
            json={
                "tx_hash": SAMPLE_TX_HASH,
                "bundle": permit["bundle"],
                "signature": permit["signature"],
            },
        )
    assert response.status_code == 200
    data = response.json()
    assert data["settlement_verified"] is True
    assert data["permit_valid"] is True
    assert data["tx_hash"] == SAMPLE_TX_HASH
    assert data["bundle_hash"] == permit["bundle_hash"]
    assert data["checks"]["tx_validated"] is True
    assert data["checks"]["action_match"] is True
    assert data["checks"]["subject_match"] is True
    assert data["checks"]["currency_match"] is True
    assert data["checks"]["amount_within_limit"] is True
    # Proof artifact should be included in the response
    artifact = data["proof_artifact"]
    assert artifact["module"] == "CompliGate"
    assert artifact["entity_id"] == SAMPLE_TX_HASH
    assert artifact["rule_version_used"] is not None
    assert artifact["decision_result"] == "SETTLED_COMPLIANT"
    assert isinstance(artifact["evaluation_context"], dict)
    assert isinstance(artifact["reason_codes"], list)
    assert isinstance(artifact["timestamp"], int)
    assert artifact["bundle_hash"] == permit["bundle_hash"]
    anchor = artifact["anchor_metadata"]
    assert anchor["tx_hash"] == SAMPLE_TX_HASH
    assert "network" in anchor
    assert isinstance(anchor["rpc_url_present"], bool)
    assert isinstance(anchor["anchored_at"], int)


def test_settle_verify_rejects_invalid_signature():
    permit = _get_valid_permit()
    response = client.post(
        "/v1/settle/verify",
        json={
            "tx_hash": SAMPLE_TX_HASH,
            "bundle": permit["bundle"],
            "signature": "aW52YWxpZHNpZ25hdHVyZQ==",
        },
    )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "invalid_permit"


def test_settle_verify_detects_unvalidated_tx():
    permit = _get_valid_permit()
    tx_data = _make_xrpl_payment_tx(
        account=VALID_SUBJECT,
        destination="rCounterparty1234567890123456789",
        currency="RLUSD",
        value=500,
        validated=False,
    )

    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settle/verify",
            json={
                "tx_hash": SAMPLE_TX_HASH,
                "bundle": permit["bundle"],
                "signature": permit["signature"],
            },
        )
    assert response.status_code == 200
    data = response.json()
    assert data["settlement_verified"] is False
    assert data["checks"]["tx_validated"] is False


def test_settle_verify_detects_wrong_currency():
    permit = _get_valid_permit()
    tx_data = _make_xrpl_payment_tx(
        account=VALID_SUBJECT,
        destination="rCounterparty1234567890123456789",
        currency="USD",
        value=500,
    )

    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settle/verify",
            json={
                "tx_hash": SAMPLE_TX_HASH,
                "bundle": permit["bundle"],
                "signature": permit["signature"],
            },
        )
    assert response.status_code == 200
    data = response.json()
    assert data["settlement_verified"] is False
    assert data["checks"]["currency_match"] is False


def test_settle_verify_detects_amount_exceeds_limit():
    permit = _get_valid_permit()
    tx_data = _make_xrpl_payment_tx(
        account=VALID_SUBJECT,
        destination="rCounterparty1234567890123456789",
        currency="RLUSD",
        value=5000001,
    )

    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settle/verify",
            json={
                "tx_hash": SAMPLE_TX_HASH,
                "bundle": permit["bundle"],
                "signature": permit["signature"],
            },
        )
    assert response.status_code == 200
    data = response.json()
    assert data["settlement_verified"] is False
    assert data["checks"]["amount_within_limit"] is False


def test_settle_verify_detects_wrong_subject():
    permit = _get_valid_permit()
    tx_data = _make_xrpl_payment_tx(
        account="rWrongAccount12345678901234567",
        destination="rCounterparty1234567890123456789",
        currency="RLUSD",
        value=500,
    )

    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settle/verify",
            json={
                "tx_hash": SAMPLE_TX_HASH,
                "bundle": permit["bundle"],
                "signature": permit["signature"],
            },
        )
    assert response.status_code == 200
    data = response.json()
    assert data["settlement_verified"] is False
    assert data["checks"]["subject_match"] is False


def test_settle_verify_detects_wrong_counterparty():
    counterparty = "rCounterparty1234567890123456789"
    permit_resp = client.post(
        "/v1/permit",
        json={"subject": VALID_SUBJECT, "amount": 500, "counterparty": counterparty},
    )
    assert permit_resp.status_code == 200
    permit = permit_resp.json()

    tx_data = _make_xrpl_payment_tx(
        account=VALID_SUBJECT,
        destination="rWrongCounterparty123456789012",
        currency="RLUSD",
        value=500,
    )

    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settle/verify",
            json={
                "tx_hash": SAMPLE_TX_HASH,
                "bundle": permit["bundle"],
                "signature": permit["signature"],
            },
        )
    assert response.status_code == 200
    data = response.json()
    assert data["settlement_verified"] is False
    assert data["checks"]["counterparty_match"] is False


def test_settle_verify_trustset():
    permit_resp = client.post(
        "/v1/permit",
        json={"subject": VALID_SUBJECT, "action": "trustset"},
    )
    assert permit_resp.status_code == 200
    permit = permit_resp.json()

    tx_data = _make_xrpl_trustset_tx(account=VALID_SUBJECT, currency="RLUSD")

    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settle/verify",
            json={
                "tx_hash": SAMPLE_TX_HASH,
                "bundle": permit["bundle"],
                "signature": permit["signature"],
            },
        )
    assert response.status_code == 200
    data = response.json()
    assert data["settlement_verified"] is True
    assert data["checks"]["action_match"] is True


def test_settle_verify_returns_502_on_rpc_failure():
    import requests as req_lib

    permit = _get_valid_permit()

    with patch("main.http_requests.post") as mock_post:
        mock_post.side_effect = req_lib.RequestException("connection refused")

        response = client.post(
            "/v1/settle/verify",
            json={
                "tx_hash": SAMPLE_TX_HASH,
                "bundle": permit["bundle"],
                "signature": permit["signature"],
            },
        )
    assert response.status_code == 502
    detail = response.json()["detail"]
    assert detail["error"] == "xrpl_rpc_failed"


def test_settle_verify_is_logged(caplog):
    permit = _get_valid_permit()
    tx_data = _make_xrpl_payment_tx(
        account=VALID_SUBJECT,
        destination="rCounterparty1234567890123456789",
        currency="RLUSD",
        value=500,
    )

    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        with caplog.at_level(logging.INFO, logger="main"):
            client.post(
                "/v1/settle/verify",
                json={
                    "tx_hash": SAMPLE_TX_HASH,
                    "bundle": permit["bundle"],
                    "signature": permit["signature"],
                },
            )

    messages = [r.message for r in caplog.records]
    assert any(m.startswith("settlement_verified") and "tx_hash=" in m for m in messages)


def test_xrpl_health_configured():
    with patch("main.http_requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        response = client.get("/v1/xrpl/health")

    assert response.status_code == 200
    data = response.json()
    assert data["configured"] is True
    assert data["reachable"] is True
    assert "network" in data
    assert "rlusd_configured" in data
    assert "demo_wallet_configured" in data


def test_xrpl_health_unreachable():
    import requests as req_lib

    with patch("main.http_requests.post") as mock_post:
        mock_post.side_effect = req_lib.RequestException("connection refused")

        response = client.get("/v1/xrpl/health")

    assert response.status_code == 200
    data = response.json()
    assert data["configured"] is True
    assert data["reachable"] is False


def test_xrpl_health_not_configured():
    with patch("main.XRPL_RPC_URL", ""):
        response = client.get("/v1/xrpl/health")
    assert response.status_code == 200
    data = response.json()
    assert data["configured"] is False
    assert data["reachable"] is False


def test_verify_rejects_bad_signature():
    permit_response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert permit_response.status_code == 200
    bundle = permit_response.json()["bundle"]

    verify_response = client.post(
        "/v1/verify",
        json={"bundle": bundle, "signature": "aW52YWxpZHNpZ25hdHVyZQ=="},
    )
    assert verify_response.status_code == 200
    assert verify_response.json()["signature_valid"] is False


def test_verify_rejects_tampered_bundle():
    permit_response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert permit_response.status_code == 200
    permit = permit_response.json()

    tampered_bundle = dict(permit["bundle"])
    tampered_bundle["subject"] = "rTamperedAddress1234567890123"

    verify_response = client.post(
        "/v1/verify",
        json={"bundle": tampered_bundle, "signature": permit["signature"]},
    )
    assert verify_response.status_code == 200
    assert verify_response.json()["signature_valid"] is False


def test_verify_response_fields():
    permit_response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert permit_response.status_code == 200
    permit = permit_response.json()

    verify_response = client.post(
        "/v1/verify",
        json={"bundle": permit["bundle"], "signature": permit["signature"]},
    )
    assert verify_response.status_code == 200
    data = verify_response.json()
    assert data["subject"] == VALID_SUBJECT
    assert data["policy_version"] == permit["bundle"]["policy"]["version"]
    assert data["action"] == permit["bundle"]["action"]
    assert data["bundle_hash"] == permit["bundle_hash"]
    assert data["constraints"] == permit["bundle"]["constraints"]


def test_permit_unsupported_action_returns_structured_error():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "action": "burn"})
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "unsupported_action"
    assert "burn" in detail["reason"]


def test_permit_amount_exceeds_max_returns_structured_error():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "amount": 5000001})
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "transaction_not_allowed"
    assert "reason" in detail


def test_permit_amount_at_max_is_accepted():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "amount": 5000000})
    assert response.status_code == 200


def test_permit_amount_below_max_is_accepted():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "amount": 500})
    assert response.status_code == 200


# -----------------------
# Logging tests
# -----------------------

def test_permit_issued_is_logged(caplog):
    with caplog.at_level(logging.INFO, logger="main"):
        client.post("/v1/permit", json={"subject": VALID_SUBJECT, "action": "transfer"})
    messages = [r.message for r in caplog.records]
    assert any(m.startswith("permit_issued") and "subject=" in m and "action=" in m and "exp=" in m for m in messages)


def test_permit_verified_is_logged(caplog):
    permit = client.post("/v1/permit", json={"subject": VALID_SUBJECT}).json()
    with caplog.at_level(logging.INFO, logger="main"):
        client.post("/v1/verify", json={"bundle": permit["bundle"], "signature": permit["signature"]})
    messages = [r.message for r in caplog.records]
    assert any(
        m.startswith("permit_verified")
        and "signature_valid=True" in m
        and "not_expired=True" in m
        for m in messages
    )


def test_settlement_verify_requested_and_success_are_logged(caplog):
    permit = _get_valid_permit()
    tx_data = _make_xrpl_payment_tx(
        account=VALID_SUBJECT,
        destination="rCounterparty1234567890123456789",
        currency="RLUSD",
        value=500,
    )

    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        with caplog.at_level(logging.INFO, logger="main"):
            client.post(
                "/v1/settle/verify",
                json={
                    "tx_hash": SAMPLE_TX_HASH,
                    "bundle": permit["bundle"],
                    "signature": permit["signature"],
                },
            )

    messages = [r.message for r in caplog.records]
    assert any(
        m.startswith("settlement_verified")
        and "tx_hash=" in m
        and "bundle_hash=" in m
        for m in messages
    )


def test_verify_expired_bundle_returns_not_expired_false():
    permit_response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert permit_response.status_code == 200
    permit = permit_response.json()

    expired_bundle = dict(permit["bundle"])
    expired_bundle["exp"] = 1  # Unix timestamp in the far past

    verify_response = client.post(
        "/v1/verify",
        json={"bundle": expired_bundle, "signature": permit["signature"]},
    )
    assert verify_response.status_code == 200
    data = verify_response.json()
    assert data["not_expired"] is False


def test_settle_verify_xrp_native_amount():
    """Settlement verification handles XRP native amounts (string drops).
    500000000 drops = 500 XRP, which matches the permit amount numerically
    but the currency mismatch (XRP vs RLUSD) should cause the check to fail.
    """
    permit = _get_valid_permit()
    # XRP native amounts are strings representing drops
    tx_data = {
        "Account": VALID_SUBJECT,
        "Destination": "rCounterparty1234567890123456789",
        "TransactionType": "Payment",
        "Amount": "500000000",  # 500 XRP in drops
        "validated": True,
    }

    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settle/verify",
            json={
                "tx_hash": SAMPLE_TX_HASH,
                "bundle": permit["bundle"],
                "signature": permit["signature"],
            },
        )
    assert response.status_code == 200
    data = response.json()
    # Currency should not match since permit expects RLUSD, not XRP
    assert data["checks"]["currency_match"] is False


# -----------------------
# Evaluation stage tests
# -----------------------

def test_evaluate_governance_returns_expected_structure():
    result = evaluate_governance()
    assert "policy_version" in result
    assert "jurisdiction" in result
    assert result["state_status"] == "active"
    assert result["state_ref"] == "gov_demo_001"


def test_evaluate_eligibility_returns_expected_structure():
    result = evaluate_eligibility()
    assert result["participant_eligible"] is True
    assert result["asset_admitted"] is True
    assert result["admission_ref"] == "admission_demo_001"


def test_evaluate_constraints_valid_action_no_amount():
    codes = evaluate_constraints("transfer", None, None)
    assert "AMOUNT_WITHIN_LIMIT" not in codes


def test_evaluate_constraints_valid_action_with_amount():
    codes = evaluate_constraints("trustset", 500, None)
    assert "AMOUNT_WITHIN_LIMIT" in codes


def test_evaluate_constraints_invalid_action_raises():
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        evaluate_constraints("payment", None, None)
    assert exc_info.value.status_code == 400
    assert exc_info.value.detail["error"] == "unsupported_action"


def test_evaluate_constraints_amount_exceeds_max_raises():
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        evaluate_constraints("transfer", 5000001, None)
    assert exc_info.value.status_code == 400
    assert exc_info.value.detail["error"] == "transaction_not_allowed"


def test_permit_decision_result_is_allow():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    assert response.json()["decision_result"] == "allow"


def test_permit_reason_codes_include_governance_and_eligibility():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    codes = response.json()["reason_codes"]
    assert "POLICY_ACTIVE" in codes
    assert "PARTICIPANT_ELIGIBLE" in codes
    assert "ASSET_ADMITTED" in codes


def test_permit_reason_codes_include_amount_within_limit_when_amount_provided():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "amount": 500})
    assert response.status_code == 200
    codes = response.json()["reason_codes"]
    assert "AMOUNT_WITHIN_LIMIT" in codes


def test_permit_reason_codes_no_amount_within_limit_when_no_amount():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    codes = response.json()["reason_codes"]
    assert "AMOUNT_WITHIN_LIMIT" not in codes
# Proof Artifact tests
# -----------------------

PROOF_ARTIFACT_FIELDS = [
    "module",
    "entity_id",
    "rule_version_used",
    "decision_result",
    "evaluation_context",
    "reason_codes",
    "timestamp",
    "bundle_hash",
    "anchor_metadata",
]


def test_proof_artifact_returns_200():
    response = client.post("/v1/proof-artifact", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200


def test_proof_artifact_has_all_required_fields():
    response = client.post("/v1/proof-artifact", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    for field in PROOF_ARTIFACT_FIELDS:
        assert field in data, f"Missing field: {field}"


def test_proof_artifact_entity_id_matches_subject():
    response = client.post("/v1/proof-artifact", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    assert data["entity_id"] == VALID_SUBJECT


def test_proof_artifact_decision_result_is_permit():
    response = client.post("/v1/proof-artifact", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    assert response.json()["decision_result"] == "permit"


def test_proof_artifact_rule_version_is_set():
    from main import POLICY_VERSION

    response = client.post("/v1/proof-artifact", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    assert response.json()["rule_version_used"] == POLICY_VERSION


def test_proof_artifact_bundle_hash_is_set():
    import re

    response = client.post("/v1/proof-artifact", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    bundle_hash = response.json()["bundle_hash"]
    # SHA-256 produces a 64-character lowercase hex string
    assert re.fullmatch(r"[0-9a-f]{64}", bundle_hash), f"Unexpected bundle_hash format: {bundle_hash}"


def test_proof_artifact_reason_codes_is_list():
    response = client.post("/v1/proof-artifact", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    assert isinstance(response.json()["reason_codes"], list)


def test_proof_artifact_evaluation_context_contains_action():
    response = client.post(
        "/v1/proof-artifact",
        json={"subject": VALID_SUBJECT, "action": "trustset"},
    )
    assert response.status_code == 200
    ctx = response.json()["evaluation_context"]
    assert ctx["action"] == "trustset"


def test_proof_artifact_validates_subject():
    response = client.post("/v1/proof-artifact", json={"subject": "invalid"})
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_subject"


def test_proof_artifact_validates_action():
    response = client.post(
        "/v1/proof-artifact",
        json={"subject": VALID_SUBJECT, "action": "burn"},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "unsupported_action"


def test_proof_artifact_validates_amount():
    response = client.post(
        "/v1/proof-artifact",
        json={"subject": VALID_SUBJECT, "amount": 5000001},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "transaction_not_allowed"


def test_proof_artifact_anchor_metadata_present():
    response = client.post("/v1/proof-artifact", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    anchor = response.json()["anchor_metadata"]
    assert isinstance(anchor, dict)
    assert "chain" in anchor


def test_proof_artifact_timestamp_is_integer():
    response = client.post("/v1/proof-artifact", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    assert isinstance(response.json()["timestamp"], int)


# -----------------------
# Permit proof_artifact tests
# -----------------------

PERMIT_PROOF_ARTIFACT_FIELDS = [
    "module",
    "entity_id",
    "rule_version_used",
    "decision_result",
    "evaluation_context",
    "reason_codes",
    "timestamp",
    "bundle_hash",
    "anchor_metadata",
]


def test_permit_includes_proof_artifact():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    assert "proof_artifact" in response.json()


def test_permit_proof_artifact_has_all_required_fields():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    proof = response.json()["proof_artifact"]
    for field in PERMIT_PROOF_ARTIFACT_FIELDS:
        assert field in proof, f"Missing field: {field}"


def test_permit_proof_artifact_module_is_compligate():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    assert response.json()["proof_artifact"]["module"] == "CompliGate"


def test_permit_proof_artifact_entity_id_matches_bundle_id():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    assert data["proof_artifact"]["entity_id"] == data["bundle"]["bundle_id"]


def test_permit_proof_artifact_rule_version_matches_policy_version():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    assert data["proof_artifact"]["rule_version_used"] == data["bundle"]["policy"]["version"]


def test_permit_proof_artifact_decision_result_is_allow():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    assert response.json()["proof_artifact"]["decision_result"] == "allow"


def test_permit_proof_artifact_evaluation_context():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    ctx = data["proof_artifact"]["evaluation_context"]
    bundle = data["bundle"]
    assert ctx["subject"] == bundle["subject"]
    assert ctx["action"] == bundle["action"]
    assert ctx["asset"] == bundle["asset"]["currency"]
    assert ctx["policy_id"] == bundle["asset"]["policy_id"]


def test_permit_proof_artifact_reason_codes_is_list():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    assert isinstance(response.json()["proof_artifact"]["reason_codes"], list)


def test_permit_proof_artifact_bundle_hash_matches_permit():
    import re

    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    bundle_hash = data["proof_artifact"]["bundle_hash"]
    assert bundle_hash == data["bundle_hash"]
    assert re.fullmatch(r"[0-9a-f]{64}", bundle_hash), f"Unexpected bundle_hash format: {bundle_hash}"


def test_permit_proof_artifact_anchor_metadata_is_empty_dict():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    assert response.json()["proof_artifact"]["anchor_metadata"] == {}


def test_permit_proof_artifact_timestamp_is_integer():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    assert isinstance(response.json()["proof_artifact"]["timestamp"], int)


# -----------------------
# XRPL/RLUSD constraint tests
# -----------------------

def test_permit_bundle_asset_classification():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    asset = response.json()["bundle"]["asset"]
    assert asset["classification"] == "regulated_stablecoin"
    assert asset["regulatory_treatment"] == "non_security"
    from main import POLICY_VERSION
    assert asset["policy_id"] == POLICY_VERSION


def test_permit_bundle_constraints_backing_signals():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    constraints = response.json()["bundle"]["constraints"]
    assert constraints["reserve_backed"] is True
    assert constraints["liquidity_verified"] is True


def test_permit_bundle_constraints_jurisdiction_identity():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    constraints = response.json()["bundle"]["constraints"]
    assert constraints["kyc_verified"] is True
    assert constraints["sanctions_check"] == "passed"
    from main import JURISDICTION
    assert constraints["jurisdiction"] == JURISDICTION


def test_permit_bundle_constraints_transaction_limits():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "amount": 100})
    assert response.status_code == 200
    constraints = response.json()["bundle"]["constraints"]
    assert constraints["amount"] == 100
    assert constraints["max_amount"] == 5000000
    assert constraints["within_limit"] is True


def test_permit_bundle_constraints_within_limit_false_not_possible():
    """Amount exceeding max_amount is rejected at validation, so within_limit is always True in response."""
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "amount": 5000001})
    assert response.status_code == 400


def test_permit_bundle_constraints_no_amount():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    constraints = response.json()["bundle"]["constraints"]
    assert constraints["amount"] is None
    assert constraints["within_limit"] is True


def test_permit_bundle_constraints_xrpl_issuer_controls():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    constraints = response.json()["bundle"]["constraints"]
    assert constraints["freeze_possible"] is True
    assert constraints["clawback_possible"] is True
    assert constraints["trustline_required"] is True


def test_permit_evaluation_context_xrpl_fields():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "amount": 250})
    assert response.status_code == 200
    ctx = response.json()["proof_artifact"]["evaluation_context"]
    assert ctx["classification"] == "regulated_stablecoin"
    assert ctx["regulatory_treatment"] == "non_security"
    assert ctx["reserve_backed"] is True
    assert ctx["liquidity_verified"] is True
    assert ctx["kyc_verified"] is True
    assert ctx["sanctions_check"] == "passed"
    assert ctx["amount"] == 250
    assert ctx["max_amount"] == 5000000
    assert ctx["within_limit"] is True
    assert ctx["freeze_possible"] is True
    assert ctx["clawback_possible"] is True
    assert ctx["trustline_required"] is True


def test_permit_reason_codes_include_xrpl_codes():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "amount": 100})
    assert response.status_code == 200
    codes = response.json()["reason_codes"]
    assert "KYC_VERIFIED" in codes
    assert "SANCTIONS_PASSED" in codes
    assert "RESERVE_BACKED" in codes
    assert "LIQUIDITY_VERIFIED" in codes
    assert "ISSUER_CONTROLS_ACTIVE" in codes
    assert "AMOUNT_WITHIN_LIMIT" in codes
# enrich_proof_artifact_with_anchor tests
# -----------------------

def _make_proof_artifact():
    """Build a ProofArtifact via the permit endpoint for use in helper tests."""
    from main import build_proof_artifact

    return build_proof_artifact(
        module="CompliGate",
        entity_id="rN7n3473SaZBCG4dFL83w7PB5XDnEHyMQX",
        rule_version_used="RLUSD_US_v1",
        decision_result="allow",
        evaluation_context={"action": "transfer"},
        reason_codes=["kyc_verified"],
        timestamp=1700000000,
        bundle_hash="abc123",
        anchor_metadata={},
    )


def test_enrich_proof_artifact_updates_anchor_metadata():
    from main import enrich_proof_artifact_with_anchor

    artifact = _make_proof_artifact()
    anchor = {"network": "xrpl_testnet", "tx_hash": "ABC123", "verified_at": 1700000001}
    enriched = enrich_proof_artifact_with_anchor(artifact, anchor)
    assert enriched.anchor_metadata == anchor


def test_enrich_proof_artifact_does_not_modify_original():
    from main import enrich_proof_artifact_with_anchor

    artifact = _make_proof_artifact()
    original_anchor = dict(artifact.anchor_metadata)
    enrich_proof_artifact_with_anchor(artifact, {"tx_id": "TX999"})
    assert artifact.anchor_metadata == original_anchor


def test_enrich_proof_artifact_returns_new_instance():
    from main import enrich_proof_artifact_with_anchor

    artifact = _make_proof_artifact()
    enriched = enrich_proof_artifact_with_anchor(artifact, {"tx_id": "TX456"})
    assert enriched is not artifact


def test_enrich_proof_artifact_preserves_other_fields():
    from main import enrich_proof_artifact_with_anchor

    artifact = _make_proof_artifact()
    anchor = {"tx_id": "TX789"}
    enriched = enrich_proof_artifact_with_anchor(artifact, anchor)
    assert enriched.module == artifact.module
    assert enriched.entity_id == artifact.entity_id
    assert enriched.rule_version_used == artifact.rule_version_used
    assert enriched.decision_result == artifact.decision_result
    assert enriched.evaluation_context == artifact.evaluation_context
    assert enriched.reason_codes == artifact.reason_codes
    assert enriched.timestamp == artifact.timestamp
    assert enriched.bundle_hash == artifact.bundle_hash


def test_enrich_proof_artifact_accepts_empty_anchor_metadata():
    from main import enrich_proof_artifact_with_anchor

    artifact = _make_proof_artifact()
    enriched = enrich_proof_artifact_with_anchor(artifact, {})
    assert enriched.anchor_metadata == {}


# -----------------------
# build_proof_link helper tests
# -----------------------


def test_build_proof_link_returns_correct_structure():
    """build_proof_link returns a dict with bundle_hash and tx_hash."""
    result = build_proof_link("bundlehash123", "txhash456")
    assert result == {"bundle_hash": "bundlehash123", "tx_hash": "txhash456"}


def test_build_proof_link_preserves_values():
    """build_proof_link preserves exact input values."""
    bh = "abc" * 20
    th = "def" * 20
    result = build_proof_link(bh, th)
    assert result["bundle_hash"] == bh
    assert result["tx_hash"] == th


# -----------------------
# XRPL Payment Endpoint Tests
# -----------------------

PAYMENT_URL = "/v1/xrpl/payment"
VALID_DESTINATION = "rN7n3473SaZBCG4dFL83w7PB5XDnEHyMQX"


def test_xrpl_payment_missing_wallet_seed():
    """Returns 400 when XRPL_DEMO_WALLET_SEED is not configured."""
    with patch("main.XRPL_DEMO_WALLET_SEED", ""):
        response = client.post(
            PAYMENT_URL,
            json={"destination": VALID_DESTINATION, "amount": "10"},
        )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "demo_wallet_not_configured"


def test_xrpl_payment_missing_rpc_url():
    """Returns 400 when XRPL_RPC_URL is not configured."""
    with patch("main.XRPL_RPC_URL", ""):
        response = client.post(
            PAYMENT_URL,
            json={"destination": VALID_DESTINATION, "amount": "10"},
        )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "xrpl_not_configured"


def test_xrpl_payment_sdk_unavailable():
    """Returns 400 when xrpl-py SDK is not installed."""
    with patch("main._XRPL_SDK_AVAILABLE", False):
        response = client.post(
            PAYMENT_URL,
            json={"destination": VALID_DESTINATION, "amount": "10"},
        )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "xrpl_sdk_unavailable"


def _mock_demo_wallet():
    """Return a MagicMock that acts as an xrpl Wallet."""
    wallet = MagicMock()
    wallet.address = "rSENDER1234567890123456789012"
    return wallet


def test_xrpl_payment_success():
    """Successful payment submission returns expected fields."""
    mock_response = MagicMock()
    mock_response.result = {
        "hash": "ABC123TXHASH",
        "meta": {"TransactionResult": "tesSUCCESS"},
    }

    with patch("main.get_demo_wallet", return_value=_mock_demo_wallet()), \
         patch("main.RLUSD_ISSUER", "rISSUER123"), \
         patch("main.RLUSD_CURRENCY", "RLUSD"), \
         patch("main.XRPL_RPC_URL", "https://s.altnet.rippletest.net:51234"), \
         patch("main.XRPL_NETWORK", "xrpl_testnet"), \
         patch("main.submit_and_wait", return_value=mock_response) as mock_submit:
        response = client.post(
            PAYMENT_URL,
            json={"destination": VALID_DESTINATION, "amount": "25"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["submitted"] is True
    assert data["tx_hash"] == "ABC123TXHASH"
    assert data["engine_result"] == "tesSUCCESS"
    assert data["network"] == "xrpl_testnet"
    assert data["currency"] == "RLUSD"
    assert data["issuer"] == "rISSUER123"
    assert data["amount"] == "25"
    assert data["destination"] == VALID_DESTINATION
    mock_submit.assert_called_once()


def test_xrpl_payment_with_memo():
    """When memo_bundle_hash is provided, submit is called with memos and proof_link is returned."""
    mock_response = MagicMock()
    mock_response.result = {
        "hash": "MEMOTXHASH",
        "meta": {"TransactionResult": "tesSUCCESS"},
    }

    with patch("main.get_demo_wallet", return_value=_mock_demo_wallet()), \
         patch("main.RLUSD_ISSUER", "rISSUER123"), \
         patch("main.RLUSD_CURRENCY", "RLUSD"), \
         patch("main.XRPL_RPC_URL", "https://s.altnet.rippletest.net:51234"), \
         patch("main.submit_and_wait", return_value=mock_response) as mock_submit:
        response = client.post(
            PAYMENT_URL,
            json={
                "destination": VALID_DESTINATION,
                "amount": 10,
                "memo_bundle_hash": "abc123hash",
            },
        )

    assert response.status_code == 200
    data = response.json()
    assert data["submitted"] is True
    assert data["tx_hash"] == "MEMOTXHASH"

    # Verify proof_link is returned with correct values
    assert "proof_link" in data
    assert data["proof_link"]["bundle_hash"] == "abc123hash"
    assert data["proof_link"]["tx_hash"] == "MEMOTXHASH"

    # Verify that the Payment object passed to submit_and_wait had memos
    call_args = mock_submit.call_args
    payment_obj = call_args[0][0]
    assert payment_obj.memos is not None
    assert len(payment_obj.memos) == 1


def test_xrpl_payment_without_memo():
    """When memo_bundle_hash is not provided, memos should be None and proof_link absent."""
    mock_response = MagicMock()
    mock_response.result = {
        "hash": "NOMEMOTXHASH",
        "meta": {"TransactionResult": "tesSUCCESS"},
    }

    with patch("main.get_demo_wallet", return_value=_mock_demo_wallet()), \
         patch("main.RLUSD_ISSUER", "rISSUER123"), \
         patch("main.RLUSD_CURRENCY", "RLUSD"), \
         patch("main.XRPL_RPC_URL", "https://s.altnet.rippletest.net:51234"), \
         patch("main.submit_and_wait", return_value=mock_response) as mock_submit:
        response = client.post(
            PAYMENT_URL,
            json={"destination": VALID_DESTINATION, "amount": "5"},
        )

    assert response.status_code == 200
    data = response.json()
    assert "proof_link" not in data
    call_args = mock_submit.call_args
    payment_obj = call_args[0][0]
    assert payment_obj.memos is None


def test_xrpl_payment_submit_failure():
    """Returns 502 when the XRPL submission fails."""
    with patch("main.get_demo_wallet", return_value=_mock_demo_wallet()), \
         patch("main.RLUSD_ISSUER", "rISSUER123"), \
         patch("main.RLUSD_CURRENCY", "RLUSD"), \
         patch("main.XRPL_RPC_URL", "https://s.altnet.rippletest.net:51234"), \
         patch("main.submit_and_wait", side_effect=Exception("connection timeout")):
        response = client.post(
            PAYMENT_URL,
            json={"destination": VALID_DESTINATION, "amount": "10"},
        )

    assert response.status_code == 502
    detail = response.json()["detail"]
    assert detail["error"] == "xrpl_submit_failed"
    assert "connection timeout" in detail["reason"]


def test_xrpl_payment_numeric_amount():
    """Numeric amount is converted to string in the response."""
    mock_response = MagicMock()
    mock_response.result = {
        "hash": "NUMTXHASH",
        "meta": {"TransactionResult": "tesSUCCESS"},
    }

    with patch("main.get_demo_wallet", return_value=_mock_demo_wallet()), \
         patch("main.RLUSD_ISSUER", "rISSUER123"), \
         patch("main.RLUSD_CURRENCY", "RLUSD"), \
         patch("main.XRPL_RPC_URL", "https://s.altnet.rippletest.net:51234"), \
         patch("main.submit_and_wait", return_value=mock_response):
        response = client.post(
            PAYMENT_URL,
            json={"destination": VALID_DESTINATION, "amount": 42},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["amount"] == "42"


def test_xrpl_payment_is_logged(caplog):
    """Successful payment submission is logged."""
    mock_response = MagicMock()
    mock_response.result = {
        "hash": "LOGTXHASH",
        "meta": {"TransactionResult": "tesSUCCESS"},
    }

    with caplog.at_level(logging.INFO), \
         patch("main.get_demo_wallet", return_value=_mock_demo_wallet()), \
         patch("main.RLUSD_ISSUER", "rISSUER123"), \
         patch("main.RLUSD_CURRENCY", "RLUSD"), \
         patch("main.XRPL_RPC_URL", "https://s.altnet.rippletest.net:51234"), \
         patch("main.submit_and_wait", return_value=mock_response):
        response = client.post(
            PAYMENT_URL,
            json={"destination": VALID_DESTINATION, "amount": "10"},
        )

    assert response.status_code == 200
    assert any("xrpl_payment_submitted" in msg for msg in caplog.messages)


# -----------------------
# POST /v1/settlement/verify tests
# -----------------------

SAMPLE_BUNDLE_HASH = "abc123def456"


def _make_compliant_rlusd_tx(
    destination="rDestination12345678901234567",
    currency="RLUSD",
    value="500",
    issuer="rISSUER",
    validated=True,
):
    """Build a mock XRPL RLUSD Payment transaction."""
    return {
        "Account": "rSender123456789012345678901",
        "Destination": destination,
        "TransactionType": "Payment",
        "Amount": {"currency": currency, "value": str(value), "issuer": issuer},
        "validated": validated,
    }


def test_settlement_verify_compliant_rlusd():
    tx_data = _make_compliant_rlusd_tx()
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "SETTLED_COMPLIANT"
    assert "CURRENCY_MATCH" in data["reason_codes"]
    assert "ISSUER_MATCH" in data["reason_codes"]
    assert "ASSET_CLASSIFIED_REGULATED_STABLECOIN" in data["reason_codes"]
    assert "RESERVE_BACKED" in data["reason_codes"]
    assert "LIQUIDITY_VERIFIED" in data["reason_codes"]
    assert "KYC_VERIFIED" in data["reason_codes"]
    assert "SANCTIONS_PASSED" in data["reason_codes"]
    assert "JURISDICTION_MATCH" in data["reason_codes"]
    assert "AMOUNT_WITHIN_LIMIT" in data["reason_codes"]
    assert "TRUSTLINE_NOT_REQUIRED" in data["reason_codes"]


def test_settlement_verify_response_has_proof_artifact():
    tx_data = _make_compliant_rlusd_tx()
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    artifact = response.json()["proof_artifact"]
    assert artifact["module"] == "CompliGate"
    assert artifact["entity_id"] == SAMPLE_TX_HASH
    assert artifact["decision_result"] == "SETTLED_COMPLIANT"
    assert artifact["bundle_hash"] == SAMPLE_BUNDLE_HASH
    assert isinstance(artifact["evaluation_context"], dict)
    assert isinstance(artifact["reason_codes"], list)
    assert isinstance(artifact["timestamp"], int)


def test_settlement_verify_evaluation_context_fields():
    tx_data = _make_compliant_rlusd_tx(destination="rDest12345678901234567890123")
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    ctx = response.json()["proof_artifact"]["evaluation_context"]
    assert ctx["bundle_hash"] == SAMPLE_BUNDLE_HASH
    assert ctx["tx_hash"] == SAMPLE_TX_HASH
    assert ctx["source_account"] == "rSender123456789012345678901"
    assert ctx["destination_account"] == "rDest12345678901234567890123"
    assert ctx["currency"] == "RLUSD"
    assert ctx["asset"] == "RLUSD"
    assert ctx["amount"] == "500"
    assert ctx["issuer"] == "rISSUER"
    assert ctx["destination"] == "rDest12345678901234567890123"
    assert ctx["memo"] is None
    assert "jurisdiction" in ctx
    assert ctx["kyc_verified"] is True
    assert ctx["sanctions_check"] == "passed"
    assert ctx["reserve_backed"] is True
    assert ctx["liquidity_verified"] is True
    assert isinstance(ctx["policy_conditions"], dict)
    assert ctx["policy_conditions"]["jurisdiction"] == ctx["jurisdiction"]
    assert ctx["policy_conditions"]["kyc_verified"] is True
    assert ctx["policy_conditions"]["sanctions"] == "passed"
    assert ctx["policy_conditions"]["reserve_backed"] is True
    assert ctx["policy_conditions"]["liquidity_verified"] is True
    assert isinstance(ctx["constraints_verified"], dict)


def test_settlement_verify_memo_parsing():
    """Memo field is parsed from XRPL transaction when present."""
    tx_data = _make_compliant_rlusd_tx()
    memo_text = "bundle_abc123"
    tx_data["Memos"] = [
        {"Memo": {"MemoData": memo_text.encode("utf-8").hex(), "MemoType": "746578742f706c61696e"}}
    ]
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    ctx = response.json()["proof_artifact"]["evaluation_context"]
    assert ctx["memo"] == memo_text


def test_settlement_verify_parses_wrapped_tx_payload():
    tx_data = {"validated": True, "ledger_index": 123, "tx": _make_compliant_rlusd_tx(value="250")}
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "SETTLED_COMPLIANT"
    ctx = data["proof_artifact"]["evaluation_context"]
    assert ctx["source_account"] == "rSender123456789012345678901"
    assert ctx["destination_account"] == "rDestination12345678901234567"
    assert ctx["currency"] == "RLUSD"
    assert ctx["amount"] == "250"
    assert data["proof_artifact"]["anchor_metadata"]["ledger_index"] == 123


def test_settlement_verify_ledger_index_in_anchor():
    """anchor_metadata includes ledger_index when present in tx data."""
    tx_data = _make_compliant_rlusd_tx()
    tx_data["ledger_index"] = 12345678
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    anchor = response.json()["proof_artifact"]["anchor_metadata"]
    assert anchor["ledger_index"] == 12345678


def test_settlement_verify_ledger_index_absent():
    """anchor_metadata omits ledger_index when not present in tx data."""
    tx_data = _make_compliant_rlusd_tx()
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    anchor = response.json()["proof_artifact"]["anchor_metadata"]
    assert "ledger_index" not in anchor


def test_settlement_verify_trustline_required_when_configured():
    """When XRPL_REQUIRE_TRUSTLINE is true, trustline constraint is validated."""
    tx_data = _make_compliant_rlusd_tx()
    with patch("main.XRPL_REQUIRE_TRUSTLINE", True), \
         patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "SETTLED_COMPLIANT"
    assert "TRUSTLINE_REQUIRED" in data["reason_codes"]


def test_settlement_verify_non_compliant_wrong_currency():
    tx_data = _make_compliant_rlusd_tx(currency="USD")
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "SETTLEMENT_NON_COMPLIANT"
    assert "ASSET_NOT_RLUSD" in data["reason_codes"]


def test_settlement_verify_non_compliant_amount_exceeds_limit():
    tx_data = _make_compliant_rlusd_tx(value="6000000")
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "SETTLEMENT_NON_COMPLIANT"
    assert "AMOUNT_EXCEEDS_LIMIT" in data["reason_codes"]


def test_settlement_verify_non_compliant_not_validated():
    tx_data = _make_compliant_rlusd_tx(validated=False)
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "SETTLEMENT_NON_COMPLIANT"
    assert "TX_NOT_VALIDATED" in data["reason_codes"]


def test_settlement_verify_non_compliant_wrong_tx_type():
    tx_data = {
        "Account": "rSender123456789012345678901",
        "TransactionType": "TrustSet",
        "LimitAmount": {"currency": "RLUSD", "value": "1000", "issuer": "rISSUER"},
        "validated": True,
    }
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "SETTLEMENT_NON_COMPLIANT"
    assert "TX_TYPE_NOT_PAYMENT" in data["reason_codes"]


def test_settlement_verify_returns_502_on_rpc_failure():
    with patch("main.fetch_xrpl_transaction", side_effect=HTTPException(status_code=502, detail={"error": "xrpl_rpc_failed"})):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 502


def test_settlement_verify_missing_bundle_hash():
    response = client.post(
        "/v1/settlement/verify",
        json={"tx_hash": SAMPLE_TX_HASH},
    )
    assert response.status_code == 422


def test_settlement_verify_missing_tx_hash():
    response = client.post(
        "/v1/settlement/verify",
        json={"bundle_hash": SAMPLE_BUNDLE_HASH},
    )
    assert response.status_code == 422


def test_settlement_verify_is_logged(caplog):
    tx_data = _make_compliant_rlusd_tx()
    with caplog.at_level(logging.INFO), \
         patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    assert any("settlement_verify" in msg for msg in caplog.messages)


def test_settlement_verify_proof_artifact_anchor_metadata():
    tx_data = _make_compliant_rlusd_tx()
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    anchor = response.json()["proof_artifact"]["anchor_metadata"]
    assert "network" in anchor
    assert anchor["tx_hash"] == SAMPLE_TX_HASH
    assert "verified_at" in anchor
    assert isinstance(anchor["verified_at"], int)


def test_settlement_verify_xrp_native_non_compliant():
    """Native XRP (not RLUSD) should be non-compliant."""
    tx_data = {
        "Account": "rSender123456789012345678901",
        "Destination": "rDest12345678901234567890123",
        "TransactionType": "Payment",
        "Amount": "1000000",
        "validated": True,
    }
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "SETTLEMENT_NON_COMPLIANT"
    assert "ASSET_NOT_RLUSD" in data["reason_codes"]


def test_settlement_verify_constraints_verified_in_context():
    tx_data = _make_compliant_rlusd_tx()
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    cv = response.json()["proof_artifact"]["evaluation_context"]["constraints_verified"]
    assert cv["tx_validated"] is True
    assert cv["tx_type_payment"] is True
    assert cv["currency_match"] is True
    assert cv["issuer_match"] is True
    assert cv["asset_classification_regulated_stablecoin"] is True
    assert cv["reserve_backed"] is True
    assert cv["liquidity_verified"] is True
    assert cv["kyc_verified"] is True
    assert cv["sanctions_check_passed"] is True
    assert cv["jurisdiction_match"] is True
    assert cv["amount_within_limit"] is True
    assert cv["trustline_required"] is True


def test_evaluate_settlement_constraints_unit_compliant():
    tx_data = _make_compliant_rlusd_tx()
    decision, reason_codes, cv = _evaluate_settlement_constraints(tx_data)
    assert decision == "SETTLED_COMPLIANT"
    assert cv["tx_validated"] is True
    assert cv["asset_classification_regulated_stablecoin"] is True


def test_evaluate_settlement_constraints_unit_non_compliant():
    tx_data = _make_compliant_rlusd_tx(currency="XYZ", validated=False)
    decision, reason_codes, cv = _evaluate_settlement_constraints(tx_data)
    assert decision == "SETTLEMENT_NON_COMPLIANT"
    assert cv["tx_validated"] is False
    assert cv["asset_classification_regulated_stablecoin"] is False


def test_settlement_verify_rlusd_issuer_enforcement():
    """When RLUSD_ISSUER is set, issuer must match."""
    tx_data = _make_compliant_rlusd_tx(issuer="rWRONG_ISSUER")
    with patch("main.RLUSD_ISSUER", "rCORRECT_ISSUER"), \
         patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "SETTLEMENT_NON_COMPLIANT"
    assert "ISSUER_MISMATCH" in data["reason_codes"]


# -----------------------
# XRPL/RLUSD Phase Tests
# -----------------------


def test_xrpl_health_configured_returns_rlusd_status():
    """XRPL health returns rlusd_configured reflecting RLUSD_ISSUER and RLUSD_CURRENCY."""
    with patch("main.http_requests.post") as mock_post, \
         patch("main.RLUSD_ISSUER", "rISSUER123"), \
         patch("main.RLUSD_CURRENCY", "RLUSD"):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp
        response = client.get("/v1/xrpl/health")
    assert response.status_code == 200
    data = response.json()
    assert data["configured"] is True
    assert data["rlusd_configured"] is True


def test_xrpl_health_unconfigured_rlusd():
    """When RLUSD_ISSUER is empty, rlusd_configured is False."""
    with patch("main.http_requests.post") as mock_post, \
         patch("main.RLUSD_ISSUER", ""), \
         patch("main.RLUSD_CURRENCY", "RLUSD"):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp
        response = client.get("/v1/xrpl/health")
    assert response.status_code == 200
    data = response.json()
    assert data["configured"] is True
    assert data["rlusd_configured"] is False


def test_xrpl_health_unconfigured_returns_all_fields():
    """Unconfigured XRPL health response includes all expected fields."""
    with patch("main.XRPL_RPC_URL", ""):
        response = client.get("/v1/xrpl/health")
    assert response.status_code == 200
    data = response.json()
    assert "configured" in data
    assert "reachable" in data
    assert "network" in data
    assert "rlusd_configured" in data
    assert "demo_wallet_configured" in data
    assert data["configured"] is False
    assert data["reachable"] is False


def test_xrpl_health_demo_wallet_configured():
    """XRPL health returns demo_wallet_configured=True when seed is set."""
    with patch("main.http_requests.post") as mock_post, \
         patch("main.XRPL_DEMO_WALLET_SEED", "sEdNotARealSeed"):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp
        response = client.get("/v1/xrpl/health")
    assert response.status_code == 200
    data = response.json()
    assert data["demo_wallet_configured"] is True


def test_xrpl_health_demo_wallet_not_configured():
    """XRPL health returns demo_wallet_configured=False when seed is empty."""
    with patch("main.http_requests.post") as mock_post, \
         patch("main.XRPL_DEMO_WALLET_SEED", ""):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp
        response = client.get("/v1/xrpl/health")
    assert response.status_code == 200
    data = response.json()
    assert data["demo_wallet_configured"] is False


def test_settlement_verify_success_mocked_xrpl_lookup():
    """Full success path: mocked XRPL tx lookup returns a compliant RLUSD payment."""
    tx_data = _make_compliant_rlusd_tx(
        destination="rDest12345678901234567890123",
        currency="RLUSD",
        value="1000",
        issuer="rISSUER",
    )
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "SETTLED_COMPLIANT"
    # Verify proof artifact is present and correct
    proof = data["proof_artifact"]
    assert proof["module"] == "CompliGate"
    assert proof["entity_id"] == SAMPLE_TX_HASH
    assert proof["decision_result"] == "SETTLED_COMPLIANT"
    # Verify evaluation context contains tx details
    ctx = proof["evaluation_context"]
    assert ctx["tx_hash"] == SAMPLE_TX_HASH
    assert ctx["asset"] == "RLUSD"
    assert ctx["amount"] == "1000"
    assert ctx["destination"] == "rDest12345678901234567890123"


def test_settlement_verify_fails_asset_not_rlusd():
    """Settlement verification rejects a non-RLUSD asset (e.g. USD)."""
    tx_data = _make_compliant_rlusd_tx(currency="USD")
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "SETTLEMENT_NON_COMPLIANT"
    assert "ASSET_NOT_RLUSD" in data["reason_codes"]
    cv = data["proof_artifact"]["evaluation_context"]["constraints_verified"]
    assert cv["asset_classification_regulated_stablecoin"] is False


def test_settlement_verify_fails_amount_exceeds_limit():
    """Settlement verification rejects a payment exceeding the MAX_AMOUNT policy limit."""
    from main import MAX_AMOUNT

    tx_data = _make_compliant_rlusd_tx(value=str(MAX_AMOUNT + 1))
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.post(
            "/v1/settlement/verify",
            json={"bundle_hash": SAMPLE_BUNDLE_HASH, "tx_hash": SAMPLE_TX_HASH},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["decision_result"] == "SETTLEMENT_NON_COMPLIANT"
    assert "AMOUNT_EXCEEDS_LIMIT" in data["reason_codes"]
    cv = data["proof_artifact"]["evaluation_context"]["constraints_verified"]
    assert cv["amount_within_limit"] is False


def test_xrpl_payment_fails_missing_wallet_seed():
    """XRPL payment returns 400 when demo wallet seed is not configured."""
    with patch("main.get_demo_wallet", return_value=None), \
         patch("main.get_xrpl_client") as mock_client:
        mock_client.return_value = MagicMock()
        response = client.post(
            "/v1/xrpl/payment",
            json={"destination": "rDestination123456789012345678", "amount": "100"},
        )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "demo_wallet_not_configured"
    assert "XRPL_DEMO_WALLET_SEED" in detail["reason"]


def test_evaluate_settlement_constraints_amount_at_max():
    """Exactly MAX_AMOUNT should be compliant."""
    from main import MAX_AMOUNT

    tx_data = _make_compliant_rlusd_tx(value=str(MAX_AMOUNT))
    decision, reason_codes, cv = _evaluate_settlement_constraints(tx_data)
    assert decision == "SETTLED_COMPLIANT"
    assert cv["amount_within_limit"] is True
    assert "AMOUNT_WITHIN_LIMIT" in reason_codes


def test_evaluate_settlement_constraints_amount_over_max():
    """One above MAX_AMOUNT should be non-compliant."""
    from main import MAX_AMOUNT

    tx_data = _make_compliant_rlusd_tx(value=str(MAX_AMOUNT + 1))
    decision, reason_codes, cv = _evaluate_settlement_constraints(tx_data)
    assert decision == "SETTLEMENT_NON_COMPLIANT"
    assert cv["amount_within_limit"] is False
    assert "AMOUNT_EXCEEDS_LIMIT" in reason_codes


# -----------------------
# GET /v1/xrpl/tx/{tx_hash} tests
# -----------------------


def test_xrpl_tx_lookup_success():
    """Transaction lookup returns normalised fields from XRPL RPC."""
    tx_data = {
        "Account": "rSender123456789012345678901",
        "Destination": "rDest12345678901234567890123",
        "TransactionType": "Payment",
        "Amount": {"currency": "RLUSD", "value": "100", "issuer": "rISSUER"},
        "validated": True,
        "meta": {"TransactionResult": "tesSUCCESS"},
    }
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.get(f"/v1/xrpl/tx/{SAMPLE_TX_HASH}")
    assert response.status_code == 200
    data = response.json()
    assert data["tx_hash"] == SAMPLE_TX_HASH
    assert data["validated"] is True
    assert data["transaction_type"] == "Payment"
    assert data["account"] == "rSender123456789012345678901"
    assert data["destination"] == "rDest12345678901234567890123"
    assert data["amount"]["currency"] == "RLUSD"
    assert data["amount"]["value"] == "100"
    assert data["engine_result"] == "tesSUCCESS"
    assert "network" in data
    assert "raw" in data


def test_xrpl_tx_lookup_unvalidated():
    """Transaction that has not been validated returns validated=False."""
    tx_data = {
        "Account": "rSender123456789012345678901",
        "TransactionType": "Payment",
        "Amount": "1000000",
        "validated": False,
    }
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.get(f"/v1/xrpl/tx/{SAMPLE_TX_HASH}")
    assert response.status_code == 200
    data = response.json()
    assert data["validated"] is False
    assert data["amount"]["currency"] == "XRP"


def test_xrpl_tx_lookup_rpc_failure():
    """Returns 502 when the XRPL RPC is unreachable."""
    with patch(
        "main.fetch_xrpl_transaction",
        side_effect=HTTPException(status_code=502, detail={"error": "xrpl_rpc_failed"}),
    ):
        response = client.get(f"/v1/xrpl/tx/{SAMPLE_TX_HASH}")
    assert response.status_code == 502


def test_xrpl_tx_lookup_is_logged(caplog):
    tx_data = {
        "Account": "rSender123456789012345678901",
        "TransactionType": "Payment",
        "Amount": {"currency": "RLUSD", "value": "50", "issuer": "rISSUER"},
        "validated": True,
    }
    with caplog.at_level(logging.INFO), \
         patch("main.fetch_xrpl_transaction", return_value=tx_data):
        client.get(f"/v1/xrpl/tx/{SAMPLE_TX_HASH}")
    assert any("xrpl_tx_lookup" in msg for msg in caplog.messages)


def test_xrpl_tx_lookup_native_xrp():
    """Native XRP amounts (string drops) are normalised correctly."""
    tx_data = {
        "Account": "rSender123456789012345678901",
        "Destination": "rDest12345678901234567890123",
        "TransactionType": "Payment",
        "Amount": "500000000",
        "validated": True,
    }
    with patch("main.fetch_xrpl_transaction", return_value=tx_data):
        response = client.get(f"/v1/xrpl/tx/{SAMPLE_TX_HASH}")
    assert response.status_code == 200
    data = response.json()
    assert data["amount"]["currency"] == "XRP"
    assert data["amount"]["value"] == "500.0"


# -----------------------
# GET /v1/xrpl/account/{address}/trustlines tests
# -----------------------


def _make_account_lines(lines):
    """Build a mock response for account_lines RPC."""
    return {"result": {"lines": lines}}


def test_xrpl_trustlines_with_rlusd():
    """Account with RLUSD trustline returns has_trustline=True."""
    lines = [
        {"currency": "RLUSD", "account": "rISSUER123", "limit": "1000000", "balance": "500"},
        {"currency": "USD", "account": "rOTHER", "limit": "50000", "balance": "0"},
    ]
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"result": {"lines": lines}}

    with patch("main.http_requests.post", return_value=mock_resp):
        response = client.get(f"/v1/xrpl/account/{VALID_SUBJECT}/trustlines")
    assert response.status_code == 200
    data = response.json()
    assert data["address"] == VALID_SUBJECT
    assert data["trustline_count"] == 2
    assert data["rlusd_trustline"]["has_trustline"] is True
    assert data["rlusd_trustline"]["currency"] == "RLUSD"
    assert data["rlusd_trustline"]["balance"] == "500"
    assert "network" in data
    assert isinstance(data["lines"], list)


def test_xrpl_trustlines_without_rlusd():
    """Account without RLUSD trustline returns has_trustline=False."""
    lines = [
        {"currency": "USD", "account": "rOTHER", "limit": "50000", "balance": "100"},
    ]
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"result": {"lines": lines}}

    with patch("main.http_requests.post", return_value=mock_resp):
        response = client.get(f"/v1/xrpl/account/{VALID_SUBJECT}/trustlines")
    assert response.status_code == 200
    data = response.json()
    assert data["rlusd_trustline"]["has_trustline"] is False


def test_xrpl_trustlines_empty_account():
    """Account with no trust lines returns empty."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"result": {"lines": []}}

    with patch("main.http_requests.post", return_value=mock_resp):
        response = client.get(f"/v1/xrpl/account/{VALID_SUBJECT}/trustlines")
    assert response.status_code == 200
    data = response.json()
    assert data["trustline_count"] == 0
    assert data["rlusd_trustline"]["has_trustline"] is False


def test_xrpl_trustlines_rpc_failure():
    """Returns 502 when XRPL RPC is unreachable."""
    import requests as req_lib

    with patch("main.http_requests.post") as mock_post:
        mock_post.side_effect = req_lib.RequestException("connection refused")
        response = client.get(f"/v1/xrpl/account/{VALID_SUBJECT}/trustlines")
    assert response.status_code == 502
    detail = response.json()["detail"]
    assert detail["error"] == "xrpl_rpc_failed"


def test_xrpl_trustlines_not_configured():
    """Returns 400 when XRPL_RPC_URL is not set."""
    with patch("main.XRPL_RPC_URL", ""):
        response = client.get(f"/v1/xrpl/account/{VALID_SUBJECT}/trustlines")
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "xrpl_not_configured"


def test_xrpl_trustlines_is_logged(caplog):
    lines = [
        {"currency": "RLUSD", "account": "rISSUER", "limit": "1000000", "balance": "0"},
    ]
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"result": {"lines": lines}}

    with caplog.at_level(logging.INFO), \
         patch("main.http_requests.post", return_value=mock_resp):
        client.get(f"/v1/xrpl/account/{VALID_SUBJECT}/trustlines")
    assert any("xrpl_trustline_check" in msg for msg in caplog.messages)


def test_xrpl_trustlines_issuer_enforcement():
    """When RLUSD_ISSUER is set, only trustlines with matching issuer are accepted."""
    lines = [
        {"currency": "RLUSD", "account": "rWRONG_ISSUER", "limit": "1000000", "balance": "0"},
    ]
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"result": {"lines": lines}}

    with patch("main.RLUSD_ISSUER", "rCORRECT_ISSUER"), \
         patch("main.http_requests.post", return_value=mock_resp):
        response = client.get(f"/v1/xrpl/account/{VALID_SUBJECT}/trustlines")
    assert response.status_code == 200
    data = response.json()
    assert data["rlusd_trustline"]["has_trustline"] is False


# -----------------------
# check_rlusd_trustline unit tests
# -----------------------


def test_check_rlusd_trustline_found():
    lines = [
        {"currency": "RLUSD", "account": "rISSUER", "limit": "500000", "balance": "100"},
    ]
    result = check_rlusd_trustline(lines)
    assert result["has_trustline"] is True
    assert result["currency"] == "RLUSD"
    assert result["limit"] == "500000"
    assert result["balance"] == "100"


def test_check_rlusd_trustline_not_found():
    lines = [
        {"currency": "USD", "account": "rOTHER", "limit": "1000", "balance": "0"},
    ]
    result = check_rlusd_trustline(lines)
    assert result["has_trustline"] is False


def test_check_rlusd_trustline_empty():
    result = check_rlusd_trustline([])
    assert result["has_trustline"] is False


# -----------------------
# POST /v1/xrpl/trustline/check tests
# -----------------------


def test_trustline_check_found():
    """POST returns trustline_exists=True when trustline is present."""
    lines = [
        {"currency": "RLUSD", "account": "rISSUER123", "limit": "1000000", "balance": "500"},
    ]
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"result": {"lines": lines}}

    with patch("main.http_requests.post", return_value=mock_resp):
        response = client.post("/v1/xrpl/trustline/check", json={"address": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    assert data["address"] == VALID_SUBJECT
    assert data["trustline_exists"] is True
    assert data["currency"] == "RLUSD"


def test_trustline_check_not_found():
    """POST returns trustline_exists=False when no matching trustline."""
    lines = [
        {"currency": "USD", "account": "rOTHER", "limit": "50000", "balance": "100"},
    ]
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"result": {"lines": lines}}

    with patch("main.http_requests.post", return_value=mock_resp):
        response = client.post("/v1/xrpl/trustline/check", json={"address": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    assert data["trustline_exists"] is False
    assert data["raw_lines_checked"] == 1


def test_trustline_check_empty_lines():
    """POST returns trustline_exists=False when account has no lines."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"result": {"lines": []}}

    with patch("main.http_requests.post", return_value=mock_resp):
        response = client.post("/v1/xrpl/trustline/check", json={"address": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    assert data["trustline_exists"] is False
    assert data["raw_lines_checked"] == 0


# -----------------------
# validate_trustline unit tests
# -----------------------


def test_validate_trustline_found_unit():
    """validate_trustline returns trustline_exists=True when a matching line exists."""
    lines = [
        {"currency": "RLUSD", "account": "rISSUER_MATCH", "limit": "1000000", "balance": "250"},
        {"currency": "USD", "account": "rOTHER", "limit": "50000", "balance": "0"},
    ]
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"result": {"lines": lines}}

    with patch("main.http_requests.post", return_value=mock_resp):
        result = validate_trustline(VALID_SUBJECT, "rISSUER_MATCH", "RLUSD")

    assert result["trustline_exists"] is True
    assert result["issuer"] == "rISSUER_MATCH"
    assert result["currency"] == "RLUSD"
    assert result["raw_lines_checked"] == 2


def test_validate_trustline_not_found_unit():
    """validate_trustline returns trustline_exists=False when no matching line exists."""
    lines = [
        {"currency": "USD", "account": "rOTHER", "limit": "50000", "balance": "100"},
    ]
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"result": {"lines": lines}}

    with patch("main.http_requests.post", return_value=mock_resp):
        result = validate_trustline(VALID_SUBJECT, "rISSUER_MATCH", "RLUSD")

    with patch("main.http_requests.post", return_value=mock_resp):
        response = client.post("/v1/xrpl/trustline/check", json={"address": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    assert data["trustline_exists"] is False
    assert data["raw_lines_checked"] == 0


def test_validate_trustline_empty_lines():
    """validate_trustline returns trustline_exists=False when account has no lines."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"result": {"lines": []}}

    with patch("main.http_requests.post", return_value=mock_resp):
        response = client.post("/v1/xrpl/trustline/check", json={"address": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    assert data["trustline_exists"] is False
    assert data["raw_lines_checked"] == 0


def test_trustline_check_invalid_address_no_r():
    """POST rejects addresses not starting with 'r'."""
    response = client.post("/v1/xrpl/trustline/check", json={"address": "X" * 30})
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_address"


def test_trustline_check_invalid_address_too_short():
    """POST rejects addresses that are too short."""
    response = client.post("/v1/xrpl/trustline/check", json={"address": "rShort"})
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_address"


def test_trustline_check_invalid_address_too_long():
    """POST rejects addresses that are too long."""
    response = client.post("/v1/xrpl/trustline/check", json={"address": "r" + "A" * 40})
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_address"


def test_trustline_check_missing_address():
    """POST rejects request with missing address field."""
    response = client.post("/v1/xrpl/trustline/check", json={})
    assert response.status_code == 422


def test_trustline_check_xrpl_not_configured():
    """POST returns 400 when XRPL_RPC_URL is not set."""
    with patch("main.XRPL_RPC_URL", ""):
        response = client.post("/v1/xrpl/trustline/check", json={"address": VALID_SUBJECT})
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "xrpl_not_configured"


def test_trustline_check_rpc_failure():
    """POST returns 502 when XRPL RPC fails."""
    import requests as req_lib

    with patch("main.http_requests.post") as mock_post:
        mock_post.side_effect = req_lib.RequestException("connection refused")
        response = client.post("/v1/xrpl/trustline/check", json={"address": VALID_SUBJECT})
    assert response.status_code == 502
    assert response.json()["detail"]["error"] == "xrpl_rpc_failed"


def test_trustline_check_issuer_enforcement():
    """When RLUSD_ISSUER is set, only matching issuer counts."""
    lines = [
        {"currency": "RLUSD", "account": "rWRONG", "limit": "1000000", "balance": "0"},
    ]
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"result": {"lines": lines}}

    with patch("main.RLUSD_ISSUER", "rISSUER"), \
         patch("main.http_requests.post", return_value=mock_resp):
        response = client.post("/v1/xrpl/trustline/check", json={"address": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    assert data["trustline_exists"] is False


def test_validate_trustline_wrong_issuer():
    """validate_trustline returns False when currency matches but issuer does not."""
    lines = [
        {"currency": "RLUSD", "account": "rWRONG_ISSUER", "limit": "1000000", "balance": "0"},
    ]
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"result": {"lines": lines}}

    with patch("main.RLUSD_ISSUER", "rCORRECT_ISSUER"), \
         patch("main.http_requests.post", return_value=mock_resp):
        response = client.post("/v1/xrpl/trustline/check", json={"address": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    assert data["trustline_exists"] is False


# -----------------------
# validate_trustline unit tests
# -----------------------


def test_validate_trustline_found():
    """validate_trustline returns trustline_exists=True when match exists."""
    lines = [
        {"currency": "RLUSD", "account": "rISSUER", "limit": "500000", "balance": "100"},
    ]
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"result": {"lines": lines}}

    with patch("main.http_requests.post", return_value=mock_resp):
        result = validate_trustline("rN7n3473SaZBCG4dFL83w7PB5XDnEHyMQX", "rISSUER", "RLUSD")
    assert result["trustline_exists"] is True
    assert result["raw_lines_checked"] == 1


def test_validate_trustline_not_found():
    """validate_trustline returns trustline_exists=False when no match."""
    lines = [
        {"currency": "USD", "account": "rOTHER", "limit": "1000", "balance": "0"},
    ]
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"result": {"lines": lines}}

    with patch("main.http_requests.post", return_value=mock_resp):
        result = validate_trustline(VALID_SUBJECT, "rCORRECT_ISSUER", "RLUSD")

    assert result["trustline_exists"] is False
    assert result["raw_lines_checked"] == 1


def test_validate_trustline_wrong_currency():
    """validate_trustline returns False when issuer matches but currency does not."""
    lines = [
        {"currency": "USD", "account": "rISSUER", "limit": "1000000", "balance": "0"},
    ]
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"result": {"lines": lines}}

    with patch("main.http_requests.post", return_value=mock_resp):
        result = validate_trustline(VALID_SUBJECT, "rISSUER", "RLUSD")
        result = validate_trustline("rN7n3473SaZBCG4dFL83w7PB5XDnEHyMQX", "rISSUER", "RLUSD")

    assert result["trustline_exists"] is False
    assert result["raw_lines_checked"] == 1


def test_validate_trustline_empty_issuer():
    """validate_trustline matches any issuer when issuer is empty."""
    lines = [
        {"currency": "RLUSD", "account": "rANY_ISSUER", "limit": "500000", "balance": "50"},
    ]
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"result": {"lines": lines}}

    with patch("main.http_requests.post", return_value=mock_resp):
        result = validate_trustline("rN7n3473SaZBCG4dFL83w7PB5XDnEHyMQX", "", "RLUSD")
    assert result["trustline_exists"] is True

def test_validate_trustline_rpc_failure():
    """validate_trustline propagates HTTPException on RPC failure."""
    import requests as req_lib

    with patch("main.http_requests.post") as mock_post:
        mock_post.side_effect = req_lib.RequestException("connection refused")
        with pytest.raises(Exception):
            validate_trustline(VALID_SUBJECT, "rISSUER", "RLUSD")
