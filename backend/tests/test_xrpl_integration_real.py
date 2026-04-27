"""Real XRPL testnet integration test.

This test is intentionally skipped by default because it submits a real
``Payment`` to the live XRPL testnet (or whatever ``XRPL_RPC_URL`` points
at) and therefore must not run in normal CI. It is opted-in to via the
``RUN_XRPL_INTEGRATION_TESTS=true`` environment variable.

When enabled, the test:

1. Requires ``XRPL_RPC_URL`` to be set (otherwise it skips).
2. Requires ``XRPL_SIGNER_SEED`` to be set (otherwise it skips).
3. Requires the seed-derived wallet to already be funded on testnet.
4. Submits a real XRP testnet Payment carrying a ``bundle_hash`` Memo.
5. Captures the network-issued ``tx_hash``.
6. Asserts that the looked-up transaction is reported as validated.
7. Asserts the on-ledger Memo equals the supplied ``bundle_hash``.
8. Asserts settlement verification against the permit returns
   ``SETTLED_COMPLIANT``.

No XRPL responses are mocked: every assertion below is made against the
real, live ledger response.
"""

from __future__ import annotations

import os
import time
import uuid

import pytest


# ---------------------------------------------------------------------------
# Module-level skip: this test is opt-in only. Setting
# ``RUN_XRPL_INTEGRATION_TESTS=true`` is the one and only way to run it –
# this guarantees normal CI (which never sets that flag) skips the file.
# ---------------------------------------------------------------------------
pytestmark = pytest.mark.skipif(
    os.getenv("RUN_XRPL_INTEGRATION_TESTS", "").lower() != "true",
    reason=(
        "Real XRPL integration test is opt-in. "
        "Set RUN_XRPL_INTEGRATION_TESTS=true to enable."
    ),
)


def _require_env(name: str) -> str:
    value = (os.getenv(name) or "").strip()
    if not value:
        pytest.skip(f"{name} is required for the real XRPL integration test")
    return value


def test_real_xrpl_testnet_payment_settles_compliant() -> None:
    """End-to-end real-network test: submit, fetch, verify SETTLED_COMPLIANT."""
    # 1. Require XRPL_RPC_URL.
    rpc_url = _require_env("XRPL_RPC_URL")
    # 2. Require XRPL_SIGNER_SEED.
    signer_seed = _require_env("XRPL_SIGNER_SEED")

    # Import xrpl-py and CompliGate modules lazily so that the module can be
    # collected (and skipped) even when the optional xrpl-py SDK or backend
    # configuration is unavailable in a default CI environment.
    xrpl_models_transactions = pytest.importorskip("xrpl.models.transactions")
    xrpl_clients = pytest.importorskip("xrpl.clients")
    xrpl_wallet = pytest.importorskip("xrpl.wallet")

    Memo = xrpl_models_transactions.Memo
    JsonRpcClient = xrpl_clients.JsonRpcClient
    Wallet = xrpl_wallet.Wallet

    from app.core import config
    from app.services.settlement_service import (
        _extract_tx_payload,
        _parse_first_memo,
        verify_settlement_against_permit,
    )
    from app.services.xrpl_service import lookup_xrpl_transaction
    from app.services.xrpl_signer_service import sign_payment_transaction
    from app.utils.hashing import proof_hash

    # 3. Require a funded testnet wallet derived from the configured seed.
    #    We do not call the faucet here: the operator must pre-fund the
    #    signer wallet before opting in to this test.
    try:
        sender = Wallet.from_seed(signer_seed)
    except Exception as exc:  # pragma: no cover - exercised only on opt-in
        pytest.fail(f"XRPL_SIGNER_SEED could not be parsed by xrpl-py: {exc}")

    # Use a fresh JSON-RPC client bound to the explicitly configured RPC
    # URL rather than the cached one in xrpl_service so that this test is
    # unambiguously talking to the operator-selected endpoint.
    client = JsonRpcClient(rpc_url)

    # The destination is required for any real Payment; default to a
    # well-known testnet account if the operator did not configure one.
    # Operators can override via ``COMPLIGATE_TESTNET_DESTINATION``.
    destination = (os.getenv("COMPLIGATE_TESTNET_DESTINATION") or "").strip()
    if not destination:
        # Fund a fresh receiver wallet so the test is self-contained when
        # no destination is configured. This mirrors the roundtrip script
        # under ``scripts/xrpl_testnet_roundtrip.py``.
        from xrpl.wallet import generate_faucet_wallet

        receiver = generate_faucet_wallet(client, debug=False)
        destination = receiver.address

    # Build a CompliGate-shaped permit bundle and compute its bundle_hash.
    now = int(time.time())
    bundle = {
        "bundle_id": str(uuid.uuid4()),
        "subject": sender.address,
        "action": "transfer",
        "asset": {
            "currency": "XRP",
            "issuer": "",
            "classification": "native",
        },
        "constraints": {
            "max_amount": 10.0,
            "allowed_counterparty": destination,
        },
        "policy": {
            "version": config.POLICY_VERSION,
            "jurisdiction": config.JURISDICTION,
        },
        "exp": now + 600,
        "nonce": str(uuid.uuid4()),
    }
    bundle_hash = proof_hash(bundle)

    # 4. Submit a real XRP testnet payment carrying the bundle_hash memo.
    memo = Memo(
        memo_data=bundle_hash.encode("utf-8").hex(),
        memo_type="text/plain".encode("utf-8").hex(),
    )

    response = sign_payment_transaction(
        client=client,
        destination=destination,
        amount="1000000",  # 1 XRP, in drops.
        memos=[memo],
        wallet=sender,
    )

    # 5. Fetch the real tx_hash issued by the network.
    tx_hash = response.result.get("hash") or ""
    assert tx_hash, f"XRPL submit did not return a tx_hash; raw result: {response.result}"

    engine_result = (
        response.result.get("meta", {}).get("TransactionResult", "")
        if isinstance(response.result.get("meta"), dict)
        else ""
    )
    assert engine_result == "tesSUCCESS", (
        f"XRPL engine result was {engine_result!r}, expected tesSUCCESS; "
        f"tx_hash={tx_hash}"
    )

    # 6. Look the transaction up on the live ledger and assert it is validated.
    lookup = lookup_xrpl_transaction(tx_hash)
    assert lookup["validated"] is True, (
        f"XRPL transaction {tx_hash} was not reported as validated by the ledger"
    )

    raw_tx = lookup.get("raw", {})
    tx_payload = _extract_tx_payload(raw_tx)

    # 7. Assert the on-ledger memo contains the bundle_hash we submitted.
    decoded_memo = _parse_first_memo(tx_payload)
    assert decoded_memo == bundle_hash, (
        f"On-ledger memo {decoded_memo!r} does not equal bundle_hash {bundle_hash!r}"
    )

    # 8. Run CompliGate's settlement verification against the fetched
    #    transaction and assert the resulting decision is SETTLED_COMPLIANT.
    verification = verify_settlement_against_permit(tx_payload, bundle)
    assert verification["settlement_verified"] is True, (
        f"Settlement verification failed: checks={verification.get('checks')} "
        f"details={verification.get('details')}"
    )

    decision_result = (
        "SETTLED_COMPLIANT"
        if verification["settlement_verified"]
        else "SETTLEMENT_NON_COMPLIANT"
    )
    assert decision_result == "SETTLED_COMPLIANT"
