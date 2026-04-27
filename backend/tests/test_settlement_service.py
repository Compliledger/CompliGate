"""Unit tests for ``verify_settlement_by_hash``.

These tests pin down the contract of ``POST /v1/settlement/verify`` after
the rewrite to a real XRPL transaction lookup:

* SETTLED_COMPLIANT requires *all* of: tx exists, tx validated, decoded
  memo contains the bundle_hash, permit exists, sender matches the permit
  subject (or ``constraints.expected_sender`` override), tx amount
  ``<=`` permit ``constraints.max_amount`` and the permit ``action`` is
  ``transfer``.
* Each individual failure surfaces a distinct reason code so callers can
  diagnose non-compliance without parsing free-form text.

The XRPL JSON-RPC call (``fetch_xrpl_transaction``) is mocked in every
test – no live network access happens here.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.services import settlement_service


VALID_SUBJECT = "rN7n3473SaZBCG4dFL83w7PB5XDnEHyMQX"
OTHER_ACCOUNT = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe"
BUNDLE_HASH = "bundle-hash-abcdef"
TX_HASH = "ABCDEF" * 10  # 60-char placeholder; not parsed by tests.


def _hex(text: str) -> str:
    return text.encode("utf-8").hex()


def _permit_context(
    *,
    subject: str = VALID_SUBJECT,
    action: str = "transfer",
    max_amount: float = 1000,
    expected_sender: str | None = None,
) -> dict:
    constraints: dict = {"max_amount": max_amount}
    if expected_sender is not None:
        constraints["expected_sender"] = expected_sender
    return {
        "bundle_hash": BUNDLE_HASH,
        "bundle": {
            "subject": subject,
            "action": action,
            "constraints": constraints,
        },
        "proof_artifact": None,
        "issued_at": 1700000000,
    }


def _tx_payload(
    *,
    validated: bool = True,
    account: str = VALID_SUBJECT,
    tx_type: str = "Payment",
    amount: str | dict | None = "100",
    memo_text: str | None = BUNDLE_HASH,
) -> dict:
    payload: dict = {
        "validated": validated,
        "TransactionType": tx_type,
        "Account": account,
        "Destination": OTHER_ACCOUNT,
        "Amount": amount if amount is not None else "0",
        "hash": TX_HASH,
    }
    if memo_text is not None:
        payload["Memos"] = [{"Memo": {"MemoData": _hex(memo_text)}}]
    return payload


def _run(*, permit_context, tx_data):
    with patch.object(settlement_service, "get_permit_context", return_value=permit_context), \
         patch.object(settlement_service, "fetch_xrpl_transaction", return_value=tx_data):
        return settlement_service.verify_settlement_by_hash(BUNDLE_HASH, TX_HASH)


def test_settlement_compliant_when_all_checks_pass():
    result = _run(
        permit_context=_permit_context(),
        tx_data=_tx_payload(amount="500"),
    )
    assert result.decision_result == "SETTLED_COMPLIANT"
    assert "TX_FOUND" in result.reason_codes
    assert "TX_VALIDATED" in result.reason_codes
    assert "BUNDLE_HASH_MEMO_MATCH" in result.reason_codes
    assert "SUBJECT_MATCH" in result.reason_codes
    assert "AMOUNT_WITHIN_LIMIT" in result.reason_codes
    assert "ACTION_MATCH" in result.reason_codes


def test_permit_not_found_raises_404():
    with patch.object(settlement_service, "get_permit_context", return_value=None):
        with pytest.raises(HTTPException) as exc_info:
            settlement_service.verify_settlement_by_hash(BUNDLE_HASH, TX_HASH)
    assert exc_info.value.status_code == 404
    assert exc_info.value.detail["error"] == "permit_not_found"


def test_tx_not_found_returns_non_compliant():
    result = _run(
        permit_context=_permit_context(),
        tx_data={"error": "txnNotFound", "status": "error"},
    )
    assert result.decision_result == "SETTLEMENT_NON_COMPLIANT"
    assert "TX_NOT_FOUND" in result.reason_codes


def test_tx_not_validated_returns_non_compliant():
    result = _run(
        permit_context=_permit_context(),
        tx_data=_tx_payload(validated=False),
    )
    assert result.decision_result == "SETTLEMENT_NON_COMPLIANT"
    assert "TX_NOT_VALIDATED" in result.reason_codes


def test_memo_missing_returns_non_compliant():
    result = _run(
        permit_context=_permit_context(),
        tx_data=_tx_payload(memo_text=None),
    )
    assert result.decision_result == "SETTLEMENT_NON_COMPLIANT"
    assert "BUNDLE_HASH_MEMO_MISSING" in result.reason_codes


def test_memo_does_not_contain_bundle_hash_returns_non_compliant():
    result = _run(
        permit_context=_permit_context(),
        tx_data=_tx_payload(memo_text="some-other-hash"),
    )
    assert result.decision_result == "SETTLEMENT_NON_COMPLIANT"
    assert "BUNDLE_HASH_MEMO_MISMATCH" in result.reason_codes


def test_subject_mismatch_returns_non_compliant():
    result = _run(
        permit_context=_permit_context(),
        tx_data=_tx_payload(account=OTHER_ACCOUNT),
    )
    assert result.decision_result == "SETTLEMENT_NON_COMPLIANT"
    assert "SUBJECT_MISMATCH" in result.reason_codes


def test_expected_sender_override_takes_precedence_over_subject():
    # Permit subject is VALID_SUBJECT but the override expects OTHER_ACCOUNT
    # so a tx from OTHER_ACCOUNT is compliant.
    result = _run(
        permit_context=_permit_context(expected_sender=OTHER_ACCOUNT),
        tx_data=_tx_payload(account=OTHER_ACCOUNT),
    )
    assert result.decision_result == "SETTLED_COMPLIANT"
    assert "SUBJECT_MATCH" in result.reason_codes


def test_amount_exceeds_max_amount_returns_non_compliant():
    result = _run(
        permit_context=_permit_context(max_amount=10),
        tx_data=_tx_payload(amount={"currency": "RLUSD", "value": "100", "issuer": "rIssuer"}),
    )
    assert result.decision_result == "SETTLEMENT_NON_COMPLIANT"
    assert "AMOUNT_EXCEEDS_LIMIT" in result.reason_codes


def test_action_mismatch_when_permit_action_is_not_transfer():
    result = _run(
        permit_context=_permit_context(action="trustset"),
        tx_data=_tx_payload(tx_type="Payment"),
    )
    assert result.decision_result == "SETTLEMENT_NON_COMPLIANT"
    assert "ACTION_MISMATCH" in result.reason_codes


def test_action_mismatch_when_tx_is_not_payment():
    result = _run(
        permit_context=_permit_context(action="transfer"),
        tx_data=_tx_payload(tx_type="TrustSet"),
    )
    assert result.decision_result == "SETTLEMENT_NON_COMPLIANT"
    assert "ACTION_MISMATCH" in result.reason_codes


def test_xrp_drops_amount_is_compared_in_xrp_units():
    # 1_000_000 drops == 1 XRP, which is <= max_amount=2.
    result = _run(
        permit_context=_permit_context(max_amount=2),
        tx_data=_tx_payload(amount="1000000"),
    )
    assert result.decision_result == "SETTLED_COMPLIANT"
    assert "AMOUNT_WITHIN_LIMIT" in result.reason_codes
