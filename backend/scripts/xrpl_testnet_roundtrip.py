#!/usr/bin/env python3
"""Real XRPL testnet roundtrip for CompliGate.

This script performs a single end-to-end roundtrip against the real
XRPL testnet. No XRPL responses are mocked — every XRPL call (faucet
funding, transaction submission, transaction lookup) hits the live
testnet via the JSON-RPC endpoint configured in ``XRPL_RPC_URL``
(defaults to ``https://s.altnet.rippletest.net:51234``).

The five steps the script executes are:

1. Submit a real XRPL testnet ``Payment`` carrying a CompliGate
   ``bundle_hash`` in a transaction Memo.
2. Capture the real ``tx_hash`` returned by the network.
3. Fetch the same ``tx_hash`` back from XRPL testnet.
4. Run CompliGate's settlement verification against the fetched
   transaction using the same permit bundle.
5. Decode the on-ledger Memo from the fetched transaction and prove
   that it equals the ``bundle_hash`` (memo ↔ bundle linkage).

The script reuses the production code paths (``sign_payment_transaction``,
``lookup_xrpl_transaction``, ``verify_settlement_against_permit``,
``proof_hash``) — it does **not** add any new XRPL or compliance
features. The compliance evaluation pipeline is intentionally not
exercised here; per the task brief the compliance provider may remain
``mock_trm`` for now and only XRPL execution and lookup must be real.

Usage (from the ``backend/`` directory)::

    python3 scripts/xrpl_testnet_roundtrip.py

Environment variables consulted:

``XRPL_RPC_URL``
    XRPL testnet JSON-RPC endpoint (default: testnet).
``XRPL_NETWORK``
    Network identifier embedded in CompliGate metadata
    (default: ``xrpl_testnet``).
``XRPL_SIGNER_SEED`` / ``XRPL_SIGNING_SEED``
    Optional. When set the sender wallet is derived from this seed and
    must already hold testnet XRP. When unset, the script funds a fresh
    sender wallet via the testnet faucet.
``COMPLIGATE_TESTNET_DESTINATION``
    Optional XRPL classic address to send the test payment to. When
    unset, the script funds a fresh receiver wallet via the testnet
    faucet.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path

# Make ``app.*`` importable when running this script directly.
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from xrpl.models.transactions import Memo  # noqa: E402
from xrpl.wallet import Wallet, generate_faucet_wallet  # noqa: E402

from app.core import config  # noqa: E402
from app.services.settlement_service import (  # noqa: E402
    _extract_tx_payload,
    _parse_first_memo,
    verify_settlement_against_permit,
)
from app.services.xrpl_service import (  # noqa: E402
    get_xrpl_client,
    lookup_xrpl_transaction,
)
from app.services.xrpl_signer_service import sign_payment_transaction  # noqa: E402
from app.utils.hashing import proof_hash  # noqa: E402


# Amount sent in the test Payment, in XRP drops (1 XRP = 1_000_000 drops).
# Small enough to leave the funded faucet balance comfortably above the
# XRPL base reserve.
PAYMENT_AMOUNT_DROPS = "1000000"  # 1 XRP


def _build_test_bundle(subject: str, destination: str) -> dict:
    """Build a CompliGate-shaped permit bundle for the roundtrip.

    The bundle uses the same canonical fields the real permit issuer
    produces (``subject``, ``action``, ``asset``, ``constraints``,
    ``policy``, ``exp``, ``nonce``) so that ``proof_hash`` and
    ``verify_settlement_against_permit`` operate on a realistic input
    rather than an ad-hoc dict.
    """
    now = int(time.time())
    return {
        "bundle_id": str(uuid.uuid4()),
        "subject": subject,
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


def _resolve_sender_wallet(client) -> Wallet:
    seed = (config.XRPL_SIGNER_SEED or config.XRPL_SIGNING_SEED).strip()
    if seed:
        print(f"[1/5] Using configured signer seed (address derived from XRPL_SIGNER_SEED)")
        return Wallet.from_seed(seed)
    print("[1/5] No signer seed configured – funding a fresh sender wallet via XRPL testnet faucet")
    return generate_faucet_wallet(client, debug=False)


def _resolve_destination(client) -> str:
    explicit = os.getenv("COMPLIGATE_TESTNET_DESTINATION", "").strip()
    if explicit:
        print(f"[1/5] Using configured destination address: {explicit}")
        return explicit
    print("[1/5] No destination configured – funding a fresh receiver wallet via XRPL testnet faucet")
    receiver = generate_faucet_wallet(client, debug=False)
    return receiver.address


def run_roundtrip() -> dict:
    client = get_xrpl_client()
    if client is None:
        raise RuntimeError(
            "XRPL client is not available – ensure xrpl-py is installed and "
            "XRPL_RPC_URL is configured (defaults to XRPL testnet)."
        )

    print(f"[0/5] XRPL endpoint:       {config.XRPL_RPC_URL}")
    print(f"[0/5] XRPL network label:  {config.XRPL_NETWORK}")

    sender = _resolve_sender_wallet(client)
    destination = _resolve_destination(client)

    print(f"[1/5] Sender address:      {sender.address}")
    print(f"[1/5] Destination address: {destination}")

    bundle = _build_test_bundle(subject=sender.address, destination=destination)
    bundle_hash = proof_hash(bundle)
    print(f"[1/5] Computed bundle_hash: {bundle_hash}")

    # Step 1: build the Payment with the bundle_hash as a Memo and submit
    # it to the real XRPL testnet. ``sign_payment_transaction`` calls
    # ``submit_and_wait`` under the hood, so the network has accepted
    # and validated the transaction by the time it returns.
    memo = Memo(
        memo_data=bundle_hash.encode("utf-8").hex(),
        memo_type="text/plain".encode("utf-8").hex(),
    )

    print("[1/5] Submitting Payment to XRPL testnet…")
    response = sign_payment_transaction(
        client=client,
        destination=destination,
        amount=PAYMENT_AMOUNT_DROPS,
        memos=[memo],
        wallet=sender,
    )

    # Step 2: extract the real tx_hash from the network's response.
    tx_hash = response.result.get("hash", "")
    engine_result = response.result.get("meta", {}).get("TransactionResult", "unknown")
    if not tx_hash:
        raise RuntimeError(f"XRPL submit did not return a tx_hash; raw result: {response.result}")
    print(f"[2/5] Real tx_hash:        {tx_hash}")
    print(f"[2/5] Engine result:       {engine_result}")

    # Step 3: fetch the transaction back from XRPL testnet using the
    # production ``lookup_xrpl_transaction`` helper, which performs a
    # real ``tx`` JSON-RPC request.
    print("[3/5] Fetching transaction back from XRPL testnet…")
    lookup = lookup_xrpl_transaction(tx_hash)
    raw_tx = lookup.get("raw", {})
    tx_payload = _extract_tx_payload(raw_tx)
    validated = lookup.get("validated", False)
    ledger_index = raw_tx.get("ledger_index") or tx_payload.get("ledger_index")
    print(f"[3/5] validated:           {validated}")
    print(f"[3/5] ledger_index:        {ledger_index}")

    # Step 5 (computed before settlement reporting so we can include the
    # linkage status in the final summary): decode the Memo from the
    # fetched transaction and compare to bundle_hash.
    decoded_memo = _parse_first_memo(tx_payload)
    memo_matches_bundle_hash = decoded_memo == bundle_hash
    print(f"[5/5] Decoded memo:        {decoded_memo}")
    print(f"[5/5] memo == bundle_hash: {memo_matches_bundle_hash}")

    # Step 4: run CompliGate's settlement verification against the
    # transaction we just fetched from the live ledger.
    print("[4/5] Running settlement verification…")
    verification = verify_settlement_against_permit(tx_payload, bundle)
    print(f"[4/5] settlement_verified: {verification['settlement_verified']}")
    for check, ok in verification["checks"].items():
        print(f"        - {check}: {ok}")

    summary = {
        "network": config.XRPL_NETWORK,
        "rpc_url": config.XRPL_RPC_URL,
        "sender": sender.address,
        "destination": destination,
        "bundle_hash": bundle_hash,
        "tx_hash": tx_hash,
        "engine_result": engine_result,
        "tx_validated": validated,
        "ledger_index": ledger_index,
        "decoded_memo": decoded_memo,
        "memo_matches_bundle_hash": memo_matches_bundle_hash,
        "proof_link": {"bundle_hash": bundle_hash, "tx_hash": tx_hash},
        "settlement_verification": verification,
    }

    print("\n=== XRPL testnet roundtrip summary ===")
    print(json.dumps(summary, indent=2, sort_keys=True, default=str))

    if not memo_matches_bundle_hash:
        raise SystemExit(
            "FAIL: bundle_hash linkage not proved – decoded memo does not equal bundle_hash"
        )
    if not validated:
        raise SystemExit("FAIL: XRPL testnet did not report the transaction as validated")

    print("\nOK: real XRPL testnet roundtrip completed and bundle_hash↔memo linkage proved.")
    return summary


if __name__ == "__main__":
    run_roundtrip()
