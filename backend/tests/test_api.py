import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import logging
from main import app, evaluate_governance, evaluate_eligibility, evaluate_constraints, verify_settlement_against_permit

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
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "amount": 1001})
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "transaction_not_allowed"
    assert detail["reason"] == "amount exceeds policy maximum"


def test_permit_amount_at_max_is_allowed():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "amount": 1000})
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
        value=1500,
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
    assert data["xrpl_configured"] is True
    assert data["reachable"] is True
    assert "network" in data


def test_xrpl_health_unreachable():
    import requests as req_lib

    with patch("main.http_requests.post") as mock_post:
        mock_post.side_effect = req_lib.RequestException("connection refused")

        response = client.get("/v1/xrpl/health")

    assert response.status_code == 200
    data = response.json()
    assert data["xrpl_configured"] is True
    assert data["reachable"] is False


def test_xrpl_health_not_configured():
    with patch("main.XRPL_RPC_URL", ""):
        response = client.get("/v1/xrpl/health")
    assert response.status_code == 200
    data = response.json()
    assert data["xrpl_configured"] is False
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
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "amount": 1001})
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "transaction_not_allowed"
    assert "reason" in detail


def test_permit_amount_at_max_is_accepted():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "amount": 1000})
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
    """Settlement verification handles XRP native amounts (string drops)."""
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
        evaluate_constraints("transfer", 1001, None)
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
        json={"subject": VALID_SUBJECT, "amount": 9999},
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
