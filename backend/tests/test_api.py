from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import logging
from main import app

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


COMMIT_PAYLOAD = {
    "bundle_hash": "abc123def456",
    "subject": VALID_SUBJECT,
    "policy_id": "RLUSD_US_v1",
    "exp": 9999999999,
    "action": "transfer",
}


def test_commit_returns_committed_response():
    mock_result = {"tx_id": "ALGO_TX_001", "status": "confirmed"}
    with patch("main.http_requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_result
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        with patch("main.ALGORAND_ADAPTER_URL", "http://adapter:8080"):
            response = client.post("/v1/commit", json=COMMIT_PAYLOAD)

    assert response.status_code == 200
    data = response.json()
    assert data["committed"] is True
    assert data["algorand_tx_id"] == "ALGO_TX_001"
    assert data["bundle_hash"] == COMMIT_PAYLOAD["bundle_hash"]
    assert data["adapter_response"] == mock_result


def test_commit_calls_adapter_with_correct_payload():
    mock_result = {"tx_id": "ALGO_TX_002"}
    with patch("main.http_requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_result
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        with patch("main.ALGORAND_ADAPTER_URL", "http://adapter:8080"):
            client.post("/v1/commit", json=COMMIT_PAYLOAD)

        called_url = mock_post.call_args[0][0]
        called_json = mock_post.call_args[1]["json"]

    assert called_url == "http://adapter:8080/v1/commit"
    assert called_json["bundle_hash"] == COMMIT_PAYLOAD["bundle_hash"]
    assert called_json["subject"] == COMMIT_PAYLOAD["subject"]
    assert called_json["policy_id"] == COMMIT_PAYLOAD["policy_id"]
    assert called_json["exp"] == COMMIT_PAYLOAD["exp"]
    assert called_json["action"] == COMMIT_PAYLOAD["action"]


def test_commit_returns_502_when_adapter_url_not_configured():
    with patch("main.ALGORAND_ADAPTER_URL", ""):
        response = client.post("/v1/commit", json=COMMIT_PAYLOAD)
    assert response.status_code == 502
    detail = response.json()["detail"]
    assert detail["error"] == "adapter_commit_failed"
    assert "ALGORAND_ADAPTER_URL" in detail["reason"]


def test_commit_returns_502_when_adapter_call_fails():
    import requests as req_lib

    with patch("main.http_requests.post") as mock_post:
        mock_post.side_effect = req_lib.RequestException("connection refused")

        with patch("main.ALGORAND_ADAPTER_URL", "http://adapter:8080"):
            response = client.post("/v1/commit", json=COMMIT_PAYLOAD)

    assert response.status_code == 502
    detail = response.json()["detail"]
    assert detail["error"] == "adapter_commit_failed"
    assert "connection refused" in detail["reason"]


def test_commit_tx_id_is_none_when_missing_from_adapter():
    mock_result = {"status": "ok"}  # no tx_id key
    with patch("main.http_requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_result
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        with patch("main.ALGORAND_ADAPTER_URL", "http://adapter:8080"):
            response = client.post("/v1/commit", json=COMMIT_PAYLOAD)

    assert response.status_code == 200
    assert response.json()["algorand_tx_id"] is None

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


def test_commit_requested_and_success_are_logged(caplog):
    mock_result = {"tx_id": "ALGO_TX_LOG_TEST"}
    with patch("main.http_requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_result
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        with patch("main.ALGORAND_ADAPTER_URL", "http://adapter:8080"):
            with caplog.at_level(logging.INFO, logger="main"):
                client.post("/v1/commit", json=COMMIT_PAYLOAD)

    messages = [r.message for r in caplog.records]
    assert any(m.startswith("commit_requested") and "bundle_hash=" in m for m in messages)
    assert any(m.startswith("commit_success") and "tx_id=" in m for m in messages)


def test_commit_failed_is_logged(caplog):
    with patch("main.ALGORAND_ADAPTER_URL", ""):
        with caplog.at_level(logging.ERROR, logger="main"):
            client.post("/v1/commit", json=COMMIT_PAYLOAD)

    messages = [r.message for r in caplog.records]
    assert any(m.startswith("commit_failed") and "reason=" in m for m in messages)


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


def test_commit_success_monkeypatch(monkeypatch):
    mock_result = {"tx_id": "ALGO_TX_MONKEYPATCH"}
    captured_calls = []

    def mock_post(url, json=None, timeout=None):
        captured_calls.append({"url": url, "json": json})
        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_result
        mock_resp.raise_for_status.return_value = None
        return mock_resp

    monkeypatch.setattr("main.http_requests.post", mock_post)
    monkeypatch.setattr("main.ALGORAND_ADAPTER_URL", "http://adapter:8080")

    response = client.post("/v1/commit", json=COMMIT_PAYLOAD)
    assert response.status_code == 200
    data = response.json()
    assert data["committed"] is True
    assert data["algorand_tx_id"] == "ALGO_TX_MONKEYPATCH"
    assert data["bundle_hash"] == COMMIT_PAYLOAD["bundle_hash"]

    assert len(captured_calls) == 1
    assert captured_calls[0]["url"] == "http://adapter:8080/v1/commit"
    assert captured_calls[0]["json"]["bundle_hash"] == COMMIT_PAYLOAD["bundle_hash"]
    assert captured_calls[0]["json"]["subject"] == COMMIT_PAYLOAD["subject"]
