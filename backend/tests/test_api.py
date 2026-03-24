from fastapi.testclient import TestClient
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
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT, "action": "payment"})
    assert response.status_code == 200
    data = response.json()
    bundle = data["bundle"]
    assert bundle["action"] == "payment"
    assert bundle["scope"] == ["payment"]


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


def test_permit_subject_validation_too_short():
    response = client.post("/v1/permit", json={"subject": "rShort"})
    assert response.status_code == 400


def test_permit_subject_validation_too_long():
    response = client.post("/v1/permit", json={"subject": "r" + "a" * 35})
    assert response.status_code == 400


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
