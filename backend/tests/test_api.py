from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import settlement as settlement_routes
from app.api.routes import xrpl as xrpl_routes
from app.core import config
from app.models.proof import build_proof_artifact
from app.models.xrpl import SettlementVerifyByHashResponse
from app.services import permit_service
from app.services import xrpl_service
from app.services import xrpl_signer_service

client = TestClient(app)
VALID_SUBJECT = "rN7n3473SaZBCG4dFL83w7PB5XDnEHyMQX"
VALID_API_KEY = "test-valid-api-key"


def test_health():
    with patch.object(config, "AUTH_API_KEYS", [VALID_API_KEY]):
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_public_key():
    with patch.object(config, "AUTH_API_KEYS", [VALID_API_KEY]):
        response = client.get("/public-key")
    assert response.status_code == 200
    data = response.json()
    assert "public_key_b64" in data
    assert "public_key_hex" in data
    assert data["public_key_hex"].startswith("0x")


def test_protected_endpoint_without_api_key():
    with patch.object(config, "AUTH_API_KEYS", [VALID_API_KEY]):
        response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})

    assert response.status_code == 401
    assert response.json() == {"detail": {"error": "unauthorized", "reason": "Missing or invalid API key"}}


def test_protected_endpoint_with_invalid_api_key():
    with patch.object(config, "AUTH_API_KEYS", [VALID_API_KEY]):
        response = client.post("/v1/permit", json={"subject": VALID_SUBJECT}, headers={"X-API-Key": "invalid-api-key"})

    assert response.status_code == 401
    assert response.json() == {"detail": {"error": "unauthorized", "reason": "Missing or invalid API key"}}


def test_protected_endpoint_with_valid_api_key():
    with patch.object(config, "AUTH_API_KEYS", [VALID_API_KEY]):
        response = client.post("/v1/permit", json={"subject": VALID_SUBJECT}, headers={"X-API-Key": VALID_API_KEY})

    assert response.status_code == 200
    data = response.json()
    assert "bundle" in data
    assert "signature" in data
    assert "bundle_hash" in data


def test_permit():
    response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})
    assert response.status_code == 200
    data = response.json()
    assert "bundle" in data
    assert "signature" in data
    assert "bundle_hash" in data


def test_permit_persists_proof_artifact_record():
    with patch.object(permit_service, "save_proof_artifact") as mock_save:
        response = client.post("/v1/permit", json={"subject": VALID_SUBJECT})

    assert response.status_code == 200
    data = response.json()
    mock_save.assert_called_once()
    assert mock_save.call_args.kwargs["bundle_hash"] == data["bundle_hash"]
    assert mock_save.call_args.kwargs["artifact_type"] == "permit_generation"
    assert mock_save.call_args.kwargs["artifact"].bundle_hash == data["bundle_hash"]


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
    with patch.object(config, "AUTH_API_KEYS", [VALID_API_KEY]), patch.object(
        xrpl_routes,
        "get_xrpl_health_status",
        return_value=expected,
    ):
        response = client.get("/v1/xrpl/health")

    assert response.status_code == 200
    assert response.json() == expected


def test_xrpl_health_is_public_when_api_key_auth_enabled():
    with patch.object(config, "AUTH_API_KEYS", ["test-key"]):
        response = client.get("/v1/xrpl/health")

    assert response.status_code == 200


def test_xrpl_trustline_check_requires_api_key_when_auth_enabled():
    expected = {
        "address": VALID_SUBJECT,
        "trustline_exists": True,
        "issuer": "rIssuer",
        "currency": "RLUSD",
        "raw_lines_checked": 1,
    }
    with patch.object(config, "AUTH_API_KEYS", ["test-key"]), patch.object(
        xrpl_routes, "validate_trustline_check", return_value=expected
    ) as mock_check:
        unauthorized_response = client.post("/v1/xrpl/trustline/check", json={"address": VALID_SUBJECT})
        authorized_response = client.post(
            "/v1/xrpl/trustline/check",
            json={"address": VALID_SUBJECT},
            headers={"X-API-Key": "test-key"},
        )

    assert unauthorized_response.status_code == 401
    assert unauthorized_response.json() == {
        "detail": {"error": "unauthorized", "reason": "Missing or invalid API key"}
    }
    assert authorized_response.status_code == 200
    assert authorized_response.json() == expected
    mock_check.assert_called_once_with(
        VALID_SUBJECT,
        config.RLUSD_ISSUER,
        config.RLUSD_CURRENCY,
        xrpl_routes.fetch_account_lines,
    )


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


# ---------------------------------------------------------------------------
# XRPL signing / payment endpoint tests for the productionized signer.
#
# These tests are fully mocked and deterministic: no real XRPL network calls
# are made, no real seeds are required to be present in the environment, and
# the SDK-derived signing wallet is either built from a freshly generated
# test seed or replaced by patching ``resolve_signer`` / ``sign_payment_transaction``.
# ---------------------------------------------------------------------------

# A throwaway seed generated solely for unit tests. It is *not* funded on any
# network and is never used to sign a real transaction (``sign_payment_transaction``
# is mocked in every test that sets this seed).
TEST_SIGNER_SEED = "sEdScwdfHd269FQy2PFTJbHjnv5fRN6"
TEST_SIGNER_ADDRESS = "rp4L5ipgNwEwf1H5cn4Sssy1SuHJAeG9UF"


def _payment_payload():
    return {
        "destination": VALID_SUBJECT,
        "amount": "10",
        "memo_bundle_hash": "bundle-hash-1",
    }


def test_xrpl_payment_signing_mode_disabled_returns_structured_error():
    """When XRPL_SIGNING_MODE=disabled the payment endpoint must refuse to sign."""
    fake_client = MagicMock(name="JsonRpcClient")
    with patch.object(xrpl_routes, "enforce_destination_trustline"), patch.object(
        xrpl_service, "get_xrpl_client", return_value=fake_client
    ), patch.object(config, "XRPL_SIGNING_ENABLED", True), patch.object(
        config, "XRPL_SIGNING_MODE", "disabled"
    ):
        response = client.post("/v1/xrpl/payment", json=_payment_payload())

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail == {
        "error": "xrpl_signing_disabled",
        "reason": "XRPL signing is disabled (XRPL_SIGNING_MODE=disabled)",
        "signing_mode": "disabled",
    }


def test_xrpl_payment_signing_enabled_flag_false_returns_structured_error():
    """XRPL_SIGNING_ENABLED=false must also yield a structured signing_disabled error."""
    fake_client = MagicMock(name="JsonRpcClient")
    with patch.object(xrpl_routes, "enforce_destination_trustline"), patch.object(
        xrpl_service, "get_xrpl_client", return_value=fake_client
    ), patch.object(config, "XRPL_SIGNING_ENABLED", False), patch.object(
        config, "XRPL_SIGNING_MODE", "seed"
    ):
        response = client.post("/v1/xrpl/payment", json=_payment_payload())

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "xrpl_signing_disabled"
    assert detail["signing_mode"] == "seed"
    assert "XRPL_SIGNING_ENABLED=false" in detail["reason"]


def test_xrpl_payment_signing_mode_seed_succeeds_when_configured():
    """With XRPL_SIGNING_MODE=seed and a configured seed, payment submits via the mocked signer."""
    fake_client = MagicMock(name="JsonRpcClient")
    fake_response = SimpleNamespace(
        result={
            "meta": {"TransactionResult": "tesSUCCESS"},
            "hash": "MOCK_TX_HASH",
        }
    )

    with patch.object(xrpl_routes, "enforce_destination_trustline"), patch.object(
        xrpl_service, "get_xrpl_client", return_value=fake_client
    ), patch.object(config, "XRPL_SIGNING_ENABLED", True), patch.object(
        config, "XRPL_SIGNING_MODE", "seed"
    ), patch.object(config, "XRPL_SIGNER_SEED", TEST_SIGNER_SEED), patch.object(
        config, "XRPL_SIGNER_ADDRESS", ""
    ), patch.object(config, "XRPL_SIGNING_SEED", ""), patch.object(
        config, "XRPL_DEMO_WALLET_SEED", ""
    ), patch.object(
        xrpl_service, "sign_payment_transaction", return_value=fake_response
    ) as mock_sign:
        response = client.post("/v1/xrpl/payment", json=_payment_payload())

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["submitted"] is True
    assert body["tx_hash"] == "MOCK_TX_HASH"
    assert body["engine_result"] == "tesSUCCESS"
    assert body["destination"] == VALID_SUBJECT
    assert body["amount"] == "10"
    assert body["proof_link"] == {"bundle_hash": "bundle-hash-1", "tx_hash": "MOCK_TX_HASH"}

    # The signer was invoked with the wallet derived from the configured seed.
    mock_sign.assert_called_once()
    call_kwargs = mock_sign.call_args.kwargs
    assert call_kwargs["client"] is fake_client
    assert call_kwargs["destination"] == VALID_SUBJECT


def test_xrpl_payment_incomplete_signer_config_returns_structured_error():
    """mode=seed but no seeds configured -> structured xrpl_signer_seed_not_configured error."""
    fake_client = MagicMock(name="JsonRpcClient")
    with patch.object(xrpl_routes, "enforce_destination_trustline"), patch.object(
        xrpl_service, "get_xrpl_client", return_value=fake_client
    ), patch.object(config, "XRPL_SIGNING_ENABLED", True), patch.object(
        config, "XRPL_SIGNING_MODE", "seed"
    ), patch.object(config, "XRPL_SIGNER_SEED", ""), patch.object(
        config, "XRPL_SIGNING_SEED", ""
    ), patch.object(config, "XRPL_DEMO_WALLET_SEED", ""):
        response = client.post("/v1/xrpl/payment", json=_payment_payload())

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail == {
        "error": "xrpl_signer_seed_not_configured",
        "reason": "XRPL_SIGNER_SEED is not configured",
        "signing_mode": "seed",
    }


def test_xrpl_payment_signer_address_mismatch_returns_structured_error():
    """If XRPL_SIGNER_ADDRESS is set but doesn't match the seed-derived address, refuse."""
    fake_client = MagicMock(name="JsonRpcClient")
    with patch.object(xrpl_routes, "enforce_destination_trustline"), patch.object(
        xrpl_service, "get_xrpl_client", return_value=fake_client
    ), patch.object(config, "XRPL_SIGNING_ENABLED", True), patch.object(
        config, "XRPL_SIGNING_MODE", "seed"
    ), patch.object(config, "XRPL_SIGNER_SEED", TEST_SIGNER_SEED), patch.object(
        config, "XRPL_SIGNER_ADDRESS", "rNotTheRightAddressXXXXXXXXXXXXXXX"
    ), patch.object(config, "XRPL_SIGNING_SEED", ""), patch.object(
        config, "XRPL_DEMO_WALLET_SEED", ""
    ):
        response = client.post("/v1/xrpl/payment", json=_payment_payload())

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "xrpl_signer_address_mismatch"
    assert detail["signing_mode"] == "seed"


def test_xrpl_health_reflects_signer_status_when_signing_disabled():
    """Health should expose signing_mode/signing_enabled and report no signer when disabled."""
    fake_resp = MagicMock()
    fake_resp.raise_for_status.return_value = None
    with patch.object(config, "XRPL_RPC_URL", "https://example.invalid"), patch.object(
        config, "XRPL_NETWORK", "xrpl_testnet"
    ), patch.object(config, "RLUSD_ISSUER", "rIssuer"), patch.object(
        config, "RLUSD_CURRENCY", "RLUSD"
    ), patch.object(config, "XRPL_SIGNING_ENABLED", False), patch.object(
        config, "XRPL_SIGNING_MODE", "disabled"
    ), patch.object(config, "XRPL_SIGNING_SEED", ""), patch.object(
        config, "XRPL_DEMO_WALLET_SEED", ""
    ), patch.object(xrpl_service.http_requests, "post", return_value=fake_resp):
        response = client.get("/v1/xrpl/health")

    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is True
    assert body["reachable"] is True
    assert body["network"] == "xrpl_testnet"
    assert body["rlusd_configured"] is True
    assert body["signing_mode"] == "disabled"
    assert body["signing_enabled"] is False
    # No seeds configured -> no signing wallet available.
    assert body["demo_wallet_configured"] is False


def test_xrpl_health_reflects_signer_status_when_seed_configured():
    """When a signing seed is configured, health should report demo_wallet_configured=True."""
    fake_resp = MagicMock()
    fake_resp.raise_for_status.return_value = None
    with patch.object(config, "XRPL_RPC_URL", "https://example.invalid"), patch.object(
        config, "XRPL_NETWORK", "xrpl_testnet"
    ), patch.object(config, "RLUSD_ISSUER", "rIssuer"), patch.object(
        config, "RLUSD_CURRENCY", "RLUSD"
    ), patch.object(config, "XRPL_SIGNING_ENABLED", True), patch.object(
        config, "XRPL_SIGNING_MODE", "seed"
    ), patch.object(config, "XRPL_SIGNING_SEED", TEST_SIGNER_SEED), patch.object(
        config, "XRPL_DEMO_WALLET_SEED", ""
    ), patch.object(xrpl_service.http_requests, "post", return_value=fake_resp):
        response = client.get("/v1/xrpl/health")

    assert response.status_code == 200
    body = response.json()
    assert body["signing_mode"] == "seed"
    assert body["signing_enabled"] is True
    assert body["demo_wallet_configured"] is True


def test_xrpl_health_reflects_unreachable_rpc_with_signer_status():
    """Health should still reflect signer status correctly when RPC is unreachable."""
    import requests as _requests

    def _raise(*_args, **_kwargs):
        raise _requests.RequestException("boom")

    with patch.object(config, "XRPL_RPC_URL", "https://example.invalid"), patch.object(
        config, "XRPL_NETWORK", "xrpl_testnet"
    ), patch.object(config, "RLUSD_ISSUER", "rIssuer"), patch.object(
        config, "RLUSD_CURRENCY", "RLUSD"
    ), patch.object(config, "XRPL_SIGNING_ENABLED", True), patch.object(
        config, "XRPL_SIGNING_MODE", "seed"
    ), patch.object(config, "XRPL_SIGNING_SEED", ""), patch.object(
        config, "XRPL_DEMO_WALLET_SEED", ""
    ), patch.object(xrpl_service.http_requests, "post", side_effect=_raise):
        response = client.get("/v1/xrpl/health")

    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is True
    assert body["reachable"] is False
    assert body["signing_mode"] == "seed"
    assert body["signing_enabled"] is True
    assert body["demo_wallet_configured"] is False


def test_resolve_signer_returns_structured_error_when_disabled():
    """Unit-level check on resolve_signer for the disabled branch."""
    with patch.object(config, "XRPL_SIGNING_ENABLED", True), patch.object(
        config, "XRPL_SIGNING_MODE", "disabled"
    ):
        resolution = xrpl_service.resolve_signer()

    assert resolution.wallet is None
    assert resolution.error == {
        "error": "xrpl_signing_disabled",
        "reason": "XRPL signing is disabled (XRPL_SIGNING_MODE=disabled)",
        "signing_mode": "disabled",
    }


def test_resolve_signer_returns_wallet_for_seed_mode_when_configured():
    """resolve_signer should return a usable wallet when mode=seed and seed is set."""
    with patch.object(config, "XRPL_SIGNING_ENABLED", True), patch.object(
        config, "XRPL_SIGNING_MODE", "seed"
    ), patch.object(config, "XRPL_SIGNER_SEED", TEST_SIGNER_SEED), patch.object(
        config, "XRPL_SIGNER_ADDRESS", ""
    ), patch.object(config, "XRPL_SIGNING_SEED", ""), patch.object(
        config, "XRPL_DEMO_WALLET_SEED", ""
    ):
        resolution = xrpl_service.resolve_signer()

    assert resolution.error is None
    assert resolution.wallet is not None
    assert resolution.wallet.address == TEST_SIGNER_ADDRESS


def test_xrpl_signer_service_is_signing_configured_tracks_seed_config():
    """The legacy is_signing_configured helper should reflect seed presence deterministically.

    Note: this helper intentionally reads the legacy ``XRPL_SIGNING_SEED`` /
    ``XRPL_DEMO_WALLET_SEED`` config attributes (not the newer
    ``XRPL_SIGNER_SEED``), so the tests below patch those legacy names.
    """
    with patch.object(config, "XRPL_SIGNING_SEED", ""), patch.object(
        config, "XRPL_DEMO_WALLET_SEED", ""
    ):
        assert xrpl_signer_service.is_signing_configured() is False

    with patch.object(config, "XRPL_SIGNING_SEED", TEST_SIGNER_SEED), patch.object(
        config, "XRPL_DEMO_WALLET_SEED", ""
    ):
        assert xrpl_signer_service.is_signing_configured() is True
