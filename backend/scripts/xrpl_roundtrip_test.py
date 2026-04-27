#!/usr/bin/env python3
"""Manual real XRPL testnet roundtrip for CompliGate.

This script performs a single end-to-end roundtrip against the real
XRPL testnet using the production CompliGate code paths:

1. Create a permit by calling ``app.services.permit_service.create_permit``
   directly (the same code path that backs ``POST /v1/permit``). The
   permit is persisted so that the settlement-verification step can
   retrieve the bundle context by ``bundle_hash``.
2. Submit a real XRPL testnet ``Payment`` that carries the permit's
   ``bundle_hash`` in a transaction Memo (using
   ``sign_payment_transaction``).
3. Capture the on-ledger ``tx_hash`` returned by XRPL.
4. Run ``app.services.settlement_service.verify_settlement_by_hash``
   (the same code path that backs ``POST /v1/settlement/verify``)
   against the live ledger.
5. Print:

   * ``bundle_hash``
   * ``tx_hash``
   * ``explorer_url`` (testnet/mainnet/devnet block-explorer link
     derived from ``XRPL_NETWORK``)
   * ``decision_result``
   * ``reason_codes``

This script is **manual** — it requires real XRPL testnet network
access and (optionally) a funded testnet account. It is intentionally
*not* part of the unit-test suite: ``backend/scripts/conftest.py``
adds it to ``collect_ignore`` so ``pytest`` does not pick it up even
though its filename matches the default ``*_test.py`` discovery
pattern.

Usage (from the ``backend/`` directory)::

    DATABASE_URL=sqlite:///./compligate_roundtrip.db \\
        python3 scripts/xrpl_roundtrip_test.py

Environment variables consulted:

``DATABASE_URL``
    **Required.** The settlement-verification step looks up the permit
    bundle in the database by ``bundle_hash``; persistence must
    therefore be enabled. ``sqlite:///./compligate_roundtrip.db`` is a
    convenient local choice.
``XRPL_RPC_URL``
    XRPL JSON-RPC endpoint (default: testnet,
    ``https://s.altnet.rippletest.net:51234``).
``XRPL_NETWORK``
    Network identifier embedded in CompliGate metadata and used to
    derive the block-explorer URL (default: ``xrpl_testnet``).
``XRPL_SIGNER_SEED``
    Optional. Seed of the testnet account that will submit the
    Payment. Must already hold testnet XRP. When unset, the script
    funds a fresh sender wallet via the XRPL testnet faucet.
``XRPL_SIGNING_ENABLED`` / ``XRPL_SIGNING_MODE``
    Must allow seed-based signing (the defaults do).
``COMPLIGATE_TESTNET_DESTINATION``
    Optional XRPL classic address to send the test payment to. When
    unset, the script funds a fresh receiver wallet via the testnet
    faucet.
``COMPLIGATE_PAYMENT_AMOUNT_DROPS``
    Optional. Amount sent in the Payment, in drops (default
    ``1000000`` = 1 XRP).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Make ``app.*`` importable when running this script directly.
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from xrpl.models.transactions import Memo  # noqa: E402
from xrpl.wallet import Wallet, generate_faucet_wallet  # noqa: E402

from app.core import config  # noqa: E402
from app.db.session import initialize_database, persistence_enabled  # noqa: E402
from app.models.permit import PermitRequest  # noqa: E402
from app.services.permit_service import create_permit  # noqa: E402
from app.services.settlement_service import verify_settlement_by_hash  # noqa: E402
from app.services.xrpl_service import get_xrpl_client  # noqa: E402
from app.services.xrpl_signer_service import sign_payment_transaction  # noqa: E402


# Default Payment amount in XRP drops (1 XRP = 1_000_000 drops). Small
# enough to leave a faucet-funded balance comfortably above the XRPL
# base reserve.
_DEFAULT_PAYMENT_AMOUNT_DROPS = "1000000"


def _explorer_url_for(network: str, tx_hash: str) -> str | None:
    """Return a block-explorer URL for ``tx_hash`` on the given network.

    Returns ``None`` when the network identifier is not recognized so
    the script never prints a misleading link.
    """
    if not tx_hash:
        return None
    label = (network or "").strip().lower()
    if label in {"xrpl_testnet", "testnet"}:
        return f"https://testnet.xrpl.org/transactions/{tx_hash}"
    if label in {"xrpl_devnet", "devnet"}:
        return f"https://devnet.xrpl.org/transactions/{tx_hash}"
    if label in {"xrpl_mainnet", "mainnet", "xrpl"}:
        return f"https://livenet.xrpl.org/transactions/{tx_hash}"
    return None


def _resolve_sender_wallet(client) -> Wallet:
    seed = (config.XRPL_SIGNER_SEED or "").strip()
    if seed:
        print("[1/5] Using configured signer seed (XRPL_SIGNER_SEED)")
        return Wallet.from_seed(seed)
    print(
        "[1/5] No XRPL_SIGNER_SEED configured – "
        "funding a fresh sender wallet via XRPL testnet faucet"
    )
    return generate_faucet_wallet(client, debug=False)


def _resolve_destination(client) -> str:
    explicit = os.getenv("COMPLIGATE_TESTNET_DESTINATION", "").strip()
    if explicit:
        print(f"[1/5] Using configured destination address: {explicit}")
        return explicit
    print(
        "[1/5] No destination configured – "
        "funding a fresh receiver wallet via XRPL testnet faucet"
    )
    receiver = generate_faucet_wallet(client, debug=False)
    return receiver.address


def _payment_amount_drops() -> str:
    raw = os.getenv("COMPLIGATE_PAYMENT_AMOUNT_DROPS", "").strip()
    return raw or _DEFAULT_PAYMENT_AMOUNT_DROPS


def run_roundtrip() -> dict:
    if not persistence_enabled():
        raise SystemExit(
            "DATABASE_URL is not set. The settlement verification step "
            "looks up the permit by bundle_hash, so a database must be "
            "configured (e.g. DATABASE_URL=sqlite:///./compligate_roundtrip.db)."
        )
    initialize_database()

    client = get_xrpl_client()
    if client is None:
        raise SystemExit(
            "XRPL client is not available – ensure xrpl-py is installed and "
            "XRPL_RPC_URL is configured (defaults to XRPL testnet)."
        )

    print(f"[0/5] XRPL endpoint:       {config.XRPL_RPC_URL}")
    print(f"[0/5] XRPL network label:  {config.XRPL_NETWORK}")

    sender = _resolve_sender_wallet(client)
    destination = _resolve_destination(client)
    amount_drops = _payment_amount_drops()

    print(f"[1/5] Sender address:      {sender.address}")
    print(f"[1/5] Destination address: {destination}")
    print(f"[1/5] Payment amount:      {amount_drops} drops")

    # Step 1: create a permit using the same backend service that backs
    # POST /v1/permit. The subject is the on-ledger sender so the
    # settlement check's subject_match constraint can be evaluated, and
    # the counterparty is the on-ledger destination.
    print("[1/5] Creating permit via create_permit (backend service)…")
    permit = create_permit(
        PermitRequest(
            subject=sender.address,
            action="transfer",
            amount=1,
            counterparty=destination,
        )
    )
    bundle_hash = permit.bundle_hash
    print(f"[1/5] Permit decision:     {permit.decision_result}")
    print(f"[1/5] Computed bundle_hash: {bundle_hash}")

    # Step 2: submit a real XRPL testnet Payment with the bundle_hash
    # as a Memo. ``sign_payment_transaction`` calls ``submit_and_wait``
    # under the hood, so the network has accepted (or rejected) the
    # transaction by the time it returns.
    memo = Memo(
        memo_data=bundle_hash.encode("utf-8").hex(),
        memo_type="text/plain".encode("utf-8").hex(),
    )

    print("[2/5] Submitting Payment to XRPL testnet…")
    response = sign_payment_transaction(
        client=client,
        destination=destination,
        amount=amount_drops,
        memos=[memo],
        wallet=sender,
    )

    # Step 3: extract the real tx_hash returned by XRPL.
    tx_hash = response.result.get("hash", "")
    engine_result = response.result.get("meta", {}).get(
        "TransactionResult", "unknown"
    )
    if not tx_hash:
        raise SystemExit(
            f"XRPL submit did not return a tx_hash; raw result: {response.result}"
        )
    explorer_url = _explorer_url_for(config.XRPL_NETWORK, tx_hash)
    print(f"[3/5] Real tx_hash:        {tx_hash}")
    print(f"[3/5] Engine result:       {engine_result}")
    if explorer_url:
        print(f"[3/5] Explorer URL:        {explorer_url}")

    # Step 4: run CompliGate's settlement verification (the same code
    # path that backs POST /v1/settlement/verify) against the live
    # ledger.
    print("[4/5] Running settlement verification by bundle_hash + tx_hash…")
    verification = verify_settlement_by_hash(bundle_hash, tx_hash)
    decision_result = verification.decision_result
    reason_codes = list(verification.reason_codes)

    # Step 5: print the required summary fields.
    print("\n=== XRPL testnet roundtrip summary ===")
    summary = {
        "bundle_hash": bundle_hash,
        "tx_hash": tx_hash,
        "explorer_url": explorer_url,
        "decision_result": decision_result,
        "reason_codes": reason_codes,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))

    print(f"\n[5/5] bundle_hash:      {bundle_hash}")
    print(f"[5/5] tx_hash:          {tx_hash}")
    print(f"[5/5] explorer_url:     {explorer_url or '(not available)'}")
    print(f"[5/5] decision_result:  {decision_result}")
    print(f"[5/5] reason_codes:     {reason_codes}")

    return summary


if __name__ == "__main__":
    run_roundtrip()
