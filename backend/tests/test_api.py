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
