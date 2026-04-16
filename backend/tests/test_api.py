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
    """When memo_bundle_hash is provided, submit is called with memos."""
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

    # Verify that the Payment object passed to submit_and_wait had memos
    call_args = mock_submit.call_args
    payment_obj = call_args[0][0]
    assert payment_obj.memos is not None
    assert len(payment_obj.memos) == 1


def test_xrpl_payment_without_memo():
    """When memo_bundle_hash is not provided, memos should be None."""
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
