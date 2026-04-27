"""Tests for the explicit XRPL settlement reason codes.

Covers the codes emitted by ``app.services.settlement_service``:

- ``XRPL_TX_FOUND`` / ``XRPL_TX_NOT_FOUND``
- ``XRPL_TX_VALIDATED`` / ``XRPL_TX_NOT_VALIDATED``
- ``BUNDLE_HASH_MEMO_MATCHED`` / ``BUNDLE_HASH_MEMO_MISSING`` /
  ``BUNDLE_HASH_MEMO_MISMATCH``
- ``PERMIT_CONTEXT_FOUND`` / ``PERMIT_CONTEXT_NOT_FOUND``
- ``AMOUNT_WITHIN_LIMIT`` / ``AMOUNT_EXCEEDS_LIMIT``
- ``SETTLEMENT_VERIFIED`` / ``SETTLEMENT_VERIFICATION_FAILED``
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.services import settlement_service


BUNDLE_HASH = "abcd1234"
TX_HASH = "DEADBEEF"
SUBJECT = "rN7n3473SaZBCG4dFL83w7PB5XDnEHyMQX"
DESTINATION = "rDest00000000000000000000000000000"


def _permit_bundle() -> dict:
    return {
        "action": "transfer",
        "subject": SUBJECT,
        "asset": {"currency": "RLUSD", "issuer": "rIssuer"},
        "constraints": {
            "max_amount": 100,
            "reserve_backed": True,
            "liquidity_verified": True,
            "kyc_verified": True,
            "sanctions_check": "passed",
            "jurisdiction": "US",
            "allowed_counterparty": DESTINATION,
        },
        "policy": {"jurisdiction": "US"},
    }


def _permit_context() -> dict:
    return {
        "bundle_hash": BUNDLE_HASH,
        "bundle": _permit_bundle(),
        "proof_artifact": {},
        "issued_at": 1700000000,
    }


def _hex_memo(text: str) -> str:
    return text.encode("utf-8").hex().upper()


def _tx_payload(*, memo: str | None, validated: bool = True, amount: str = "10") -> dict:
    payload = {
        "TransactionType": "Payment",
        "Account": SUBJECT,
        "Destination": DESTINATION,
        "Amount": {"currency": "RLUSD", "issuer": "rIssuer", "value": amount},
        "validated": validated,
        "ledger_index": 12345,
    }
    if memo is not None:
        payload["Memos"] = [
            {"Memo": {"MemoData": _hex_memo(memo), "MemoType": _hex_memo("text/plain")}}
        ]
    return payload


def _run(*, tx_data: dict, permit_context=_permit_context):
    with patch.object(
        settlement_service, "get_permit_context", return_value=permit_context()
    ), patch.object(
        settlement_service, "fetch_xrpl_transaction", return_value=tx_data
    ), patch.object(
        settlement_service.config, "XRPL_REQUIRE_TRUSTLINE", False
    ), patch.object(
        settlement_service.config, "JURISDICTION", "US"
    ):
        return settlement_service.verify_settlement_by_hash(BUNDLE_HASH, TX_HASH)


def test_permit_context_not_found_raises_with_reason_code():
    with patch.object(settlement_service, "get_permit_context", return_value=None):
        with pytest.raises(HTTPException) as exc_info:
            settlement_service.verify_settlement_by_hash(BUNDLE_HASH, TX_HASH)
    assert exc_info.value.status_code == 404
    assert exc_info.value.detail["reason_code"] == "PERMIT_CONTEXT_NOT_FOUND"


def test_compliant_settlement_emits_expected_reason_codes():
    tx_data = _tx_payload(memo=BUNDLE_HASH)
    result = _run(tx_data=tx_data)
    codes = result.reason_codes

    assert "PERMIT_CONTEXT_FOUND" in codes
    assert "XRPL_TX_FOUND" in codes
    assert "XRPL_TX_VALIDATED" in codes
    assert "XRPL_TX_NOT_VALIDATED" not in codes
    assert "BUNDLE_HASH_MEMO_MATCHED" in codes
    assert "BUNDLE_HASH_MEMO_MISSING" not in codes
    assert "BUNDLE_HASH_MEMO_MISMATCH" not in codes
    assert "AMOUNT_WITHIN_LIMIT" in codes
    assert "SETTLEMENT_VERIFIED" in codes
    assert "SETTLEMENT_VERIFICATION_FAILED" not in codes
    assert result.decision_result == "SETTLED_COMPLIANT"


def test_missing_memo_emits_bundle_hash_memo_missing_and_failure():
    tx_data = _tx_payload(memo=None)
    result = _run(tx_data=tx_data)
    codes = result.reason_codes
    assert "BUNDLE_HASH_MEMO_MISSING" in codes
    assert "BUNDLE_HASH_MEMO_MATCHED" not in codes
    assert "SETTLEMENT_VERIFICATION_FAILED" in codes
    assert result.decision_result == "SETTLEMENT_NON_COMPLIANT"


def test_mismatched_memo_emits_bundle_hash_memo_mismatch_and_failure():
    tx_data = _tx_payload(memo="not-the-bundle-hash")
    result = _run(tx_data=tx_data)
    codes = result.reason_codes
    assert "BUNDLE_HASH_MEMO_MISMATCH" in codes
    assert "BUNDLE_HASH_MEMO_MATCHED" not in codes
    assert "SETTLEMENT_VERIFICATION_FAILED" in codes


def test_unvalidated_tx_emits_xrpl_tx_not_validated():
    tx_data = _tx_payload(memo=BUNDLE_HASH, validated=False)
    result = _run(tx_data=tx_data)
    codes = result.reason_codes
    assert "XRPL_TX_NOT_VALIDATED" in codes
    assert "XRPL_TX_VALIDATED" not in codes
    # Legacy code preserved for backwards compatibility.
    assert "TX_NOT_VALIDATED" in codes
    assert "SETTLEMENT_VERIFICATION_FAILED" in codes


def test_tx_not_found_emits_xrpl_tx_not_found():
    tx_data = {"error": "txnNotFound", "validated": False}
    result = _run(tx_data=tx_data)
    codes = result.reason_codes
    assert "XRPL_TX_NOT_FOUND" in codes
    assert "XRPL_TX_FOUND" not in codes
    assert "SETTLEMENT_VERIFICATION_FAILED" in codes


def test_amount_exceeds_limit_emits_failure_code():
    tx_data = _tx_payload(memo=BUNDLE_HASH, amount="1000")  # > max_amount=100
    result = _run(tx_data=tx_data)
    codes = result.reason_codes
    assert "AMOUNT_EXCEEDS_LIMIT" in codes
    assert "AMOUNT_WITHIN_LIMIT" not in codes
    assert "SETTLEMENT_VERIFICATION_FAILED" in codes
