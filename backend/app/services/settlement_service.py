from __future__ import annotations

import time
from fastapi import HTTPException

from app.core import config
from app.models.proof import build_proof_artifact
from app.models.xrpl import SettlementVerifyByHashResponse
from app.services.policy_service import ASSET_CLASSIFICATION_REGULATED_STABLECOIN
from app.services.storage_service import get_permit_context
from app.services.xrpl_service import fetch_xrpl_transaction as _fetch_xrpl_transaction
from app.services.xrpl_service import decode_memo_hex, extract_bundle_hash_from_tx, normalize_xrpl_amount


def fetch_xrpl_transaction(tx_hash: str) -> dict:
    return _fetch_xrpl_transaction(tx_hash)


def verify_settlement_against_permit(
    tx_data: dict,
    bundle: dict,
) -> dict:
    checks: dict[str, bool] = {}
    details: dict[str, str] = {}

    tx_validated = tx_data.get("validated", False)
    checks["tx_validated"] = tx_validated
    if not tx_validated:
        details["tx_validated"] = "Transaction has not been validated on ledger"

    tx_type = tx_data.get("TransactionType", "")
    permit_action = bundle.get("action", "")
    action_map = {"transfer": "Payment", "trustset": "TrustSet"}
    expected_type = action_map.get(permit_action, "")
    action_match = tx_type == expected_type
    checks["action_match"] = action_match
    if not action_match:
        details["action_match"] = f"Expected {expected_type}, got {tx_type}"

    tx_account = tx_data.get("Account", "")
    permit_subject = bundle.get("subject", "")
    subject_match = tx_account == permit_subject
    checks["subject_match"] = subject_match
    if not subject_match:
        details["subject_match"] = f"Expected {permit_subject}, got {tx_account}"

    constraints = bundle.get("constraints", {})
    asset = bundle.get("asset", {})
    expected_currency = asset.get("currency", config.CURRENCY)

    if tx_type == "Payment":
        amount = tx_data.get("Amount", {})
        if isinstance(amount, dict):
            tx_currency = amount.get("currency", "")
            tx_value = float(amount.get("value", "0"))
        else:
            tx_currency = "XRP"
            try:
                tx_value = int(amount) / 1_000_000 if amount else 0
            except (ValueError, TypeError):
                tx_value = 0

        currency_match = tx_currency == expected_currency
        checks["currency_match"] = currency_match
        if not currency_match:
            details["currency_match"] = f"Expected {expected_currency}, got {tx_currency}"

        max_amount = constraints.get("max_amount")
        if max_amount is not None:
            amount_ok = tx_value <= max_amount
            checks["amount_within_limit"] = amount_ok
            if not amount_ok:
                details["amount_within_limit"] = f"Transaction amount {tx_value} exceeds permit max {max_amount}"
        else:
            checks["amount_within_limit"] = True

        allowed_counterparty = constraints.get("allowed_counterparty")
        tx_destination = tx_data.get("Destination", "")
        if allowed_counterparty:
            counterparty_match = tx_destination == allowed_counterparty
            checks["counterparty_match"] = counterparty_match
            if not counterparty_match:
                details["counterparty_match"] = f"Expected {allowed_counterparty}, got {tx_destination}"
        else:
            checks["counterparty_match"] = True

    elif tx_type == "TrustSet":
        limit_amount = tx_data.get("LimitAmount", {})
        tx_currency = limit_amount.get("currency", "") if isinstance(limit_amount, dict) else ""
        currency_match = tx_currency == expected_currency
        checks["currency_match"] = currency_match
        if not currency_match:
            details["currency_match"] = f"Expected {expected_currency}, got {tx_currency}"
        checks["amount_within_limit"] = True
        checks["counterparty_match"] = True
    else:
        checks["currency_match"] = False
        details["currency_match"] = f"Unsupported transaction type: {tx_type}"
        checks["amount_within_limit"] = False
        checks["counterparty_match"] = False

    all_passed = all(checks.values())
    return {
        "settlement_verified": all_passed,
        "checks": checks,
        "details": details,
    }


def _evaluate_settlement_constraints(
    tx_data: dict,
    permit_bundle: dict | None = None,
) -> tuple[str, list[str], dict]:
    reason_codes: list[str] = []
    constraints_verified: dict[str, bool] = {}
    compliant = True

    # -- XRPL transaction presence --
    # ``fetch_xrpl_transaction`` returns the parsed JSON-RPC ``result`` dict.
    # When the node could not locate the transaction, the result carries an
    # ``error`` (e.g. ``txnNotFound``) and no transaction fields. Surface this
    # explicitly via the ``XRPL_TX_FOUND`` / ``XRPL_TX_NOT_FOUND`` codes.
    tx_error = tx_data.get("error") if isinstance(tx_data, dict) else None
    tx_found = bool(tx_data) and not tx_error and bool(tx_data.get("TransactionType"))
    constraints_verified["tx_found"] = tx_found
    if tx_found:
        reason_codes.append("XRPL_TX_FOUND")
    else:
        reason_codes.append("XRPL_TX_NOT_FOUND")
        compliant = False

    tx_validated = tx_data.get("validated", False)
    constraints_verified["tx_validated"] = tx_validated
    if tx_validated:
        reason_codes.append("XRPL_TX_VALIDATED")
    else:
        reason_codes.append("XRPL_TX_NOT_VALIDATED")
        # Preserve the legacy ``TX_NOT_VALIDATED`` code for backwards
        # compatibility with existing consumers.
        reason_codes.append("TX_NOT_VALIDATED")
        compliant = False

    tx_type = tx_data.get("TransactionType", "")
    action_map = {"transfer": "Payment", "trustset": "TrustSet"}
    permit_action = (permit_bundle or {}).get("action")
    if permit_bundle and not permit_action:
        constraints_verified["permit_action_present"] = False
        reason_codes.append("PERMIT_CONTEXT_ACTION_MISSING")
        compliant = False
    expected_tx_type = action_map.get(permit_action or "transfer", "Payment")
    tx_type_matches_permit = tx_type == expected_tx_type
    constraints_verified["tx_type_matches_permit"] = tx_type_matches_permit
    if tx_type_matches_permit:
        reason_codes.append("TX_TYPE_MATCHES_PERMIT")
    else:
        reason_codes.append("TX_TYPE_MISMATCH_PERMIT" if permit_bundle else "TX_TYPE_NOT_PAYMENT")
        compliant = False
    constraints_verified["tx_type_payment"] = tx_type == "Payment"

    permit_subject = (permit_bundle or {}).get("subject")
    if permit_subject:
        subject_match = tx_data.get("Account", "") == permit_subject
        constraints_verified["subject_match"] = subject_match
        if subject_match:
            reason_codes.append("SUBJECT_MATCH")
        else:
            reason_codes.append("SUBJECT_MISMATCH")
            compliant = False

    amount_raw = tx_data.get("Amount", {})
    amount_info = normalize_xrpl_amount(amount_raw)
    tx_currency = amount_info["currency"]
    tx_issuer = amount_info["issuer"]
    tx_value_str = amount_info["value"]
    try:
        tx_value = float(tx_value_str)
    except (ValueError, TypeError):
        tx_value = 0.0

    tx_destination = tx_data.get("Destination", "")

    if permit_bundle:
        permit_asset = permit_bundle.get("asset", {})
        expected_currency = permit_asset.get("currency", "")
        expected_issuer = permit_asset.get("issuer", "")
        if not expected_currency:
            constraints_verified["permit_currency_present"] = False
            reason_codes.append("PERMIT_CONTEXT_CURRENCY_MISSING")
            compliant = False
            expected_currency = config.RLUSD_CURRENCY
        if not expected_issuer:
            constraints_verified["permit_issuer_present"] = False
            reason_codes.append("PERMIT_CONTEXT_ISSUER_MISSING")
            compliant = False
    else:
        expected_currency = config.RLUSD_CURRENCY
        expected_issuer = config.RLUSD_ISSUER

    currency_match = tx_currency == expected_currency
    constraints_verified["currency_match"] = currency_match
    if currency_match:
        reason_codes.append("CURRENCY_MATCH")
    else:
        reason_codes.append("CURRENCY_MISMATCH")
        compliant = False

    if expected_issuer:
        issuer_ok = tx_issuer == expected_issuer
        constraints_verified["issuer_match"] = issuer_ok
        if issuer_ok:
            reason_codes.append("ISSUER_MATCH")
        else:
            reason_codes.append("ISSUER_MISMATCH")
            compliant = False
    else:
        constraints_verified["issuer_match"] = True
        reason_codes.append("ISSUER_MATCH")

    asset_is_rlusd = currency_match and constraints_verified["issuer_match"]
    constraints_verified["asset_classification_regulated_stablecoin"] = asset_is_rlusd
    if asset_is_rlusd:
        reason_codes.append("ASSET_CLASSIFIED_REGULATED_STABLECOIN")
    else:
        reason_codes.append("ASSET_NOT_RLUSD")
        compliant = False

    permit_constraints = (permit_bundle or {}).get("constraints", {})

    constraints_verified["reserve_backed"] = bool(permit_constraints.get("reserve_backed")) if permit_bundle else False
    if constraints_verified["reserve_backed"]:
        reason_codes.append("RESERVE_BACKED")
    else:
        reason_codes.append("RESERVE_NOT_VERIFIED")
        compliant = False

    constraints_verified["liquidity_verified"] = bool(permit_constraints.get("liquidity_verified")) if permit_bundle else False
    if constraints_verified["liquidity_verified"]:
        reason_codes.append("LIQUIDITY_VERIFIED")
    else:
        reason_codes.append("LIQUIDITY_NOT_VERIFIED")
        compliant = False

    constraints_verified["kyc_verified"] = bool(permit_constraints.get("kyc_verified")) if permit_bundle else False
    if constraints_verified["kyc_verified"]:
        reason_codes.append("KYC_VERIFIED")
    else:
        reason_codes.append("KYC_NOT_VERIFIED")
        compliant = False

    sanctions_value = permit_constraints.get("sanctions_check") if permit_bundle else None
    sanctions_passed = sanctions_value == "passed"
    constraints_verified["sanctions_check_passed"] = sanctions_passed
    if sanctions_passed:
        reason_codes.append("SANCTIONS_PASSED")
    else:
        reason_codes.append("SANCTIONS_NOT_VERIFIED")
        compliant = False

    permit_jurisdiction = (permit_bundle or {}).get("policy", {}).get("jurisdiction") or permit_constraints.get("jurisdiction")
    jurisdiction_match = permit_jurisdiction == config.JURISDICTION
    constraints_verified["jurisdiction_match"] = jurisdiction_match
    if jurisdiction_match:
        reason_codes.append("JURISDICTION_MATCH")
    else:
        reason_codes.append("JURISDICTION_MISMATCH")
        compliant = False

    if permit_bundle:
        max_amount = permit_constraints.get("max_amount")
        if max_amount is None:
            constraints_verified["permit_max_amount_present"] = False
            reason_codes.append("PERMIT_CONTEXT_MAX_AMOUNT_MISSING")
            amount_ok = False
        else:
            amount_ok = tx_value <= max_amount
    else:
        amount_ok = tx_value <= MAX_AMOUNT
    constraints_verified["amount_within_limit"] = amount_ok
    if amount_ok:
        reason_codes.append("AMOUNT_WITHIN_LIMIT")
    else:
        reason_codes.append("AMOUNT_EXCEEDS_LIMIT")
        compliant = False

    allowed_counterparty = permit_constraints.get("allowed_counterparty")
    if allowed_counterparty:
        counterparty_match = tx_destination == allowed_counterparty
        constraints_verified["counterparty_match"] = counterparty_match
        if counterparty_match:
            reason_codes.append("COUNTERPARTY_MATCH")
        else:
            reason_codes.append("COUNTERPARTY_MISMATCH")
            compliant = False

    if config.XRPL_REQUIRE_TRUSTLINE:
        trustline_satisfied = tx_validated and tx_type_matches_permit
        constraints_verified["trustline_required"] = trustline_satisfied
        if trustline_satisfied:
            reason_codes.append("TRUSTLINE_REQUIRED")
        else:
            reason_codes.append("TRUSTLINE_NOT_SATISFIED")
            compliant = False
    else:
        constraints_verified["trustline_required"] = True
        reason_codes.append("TRUSTLINE_NOT_REQUIRED")

    decision = "SETTLED_COMPLIANT" if compliant else "SETTLEMENT_NON_COMPLIANT"
    return decision, reason_codes, constraints_verified


def _extract_tx_payload(tx_data: dict) -> dict:
    nested_tx = tx_data.get("tx")
    if isinstance(nested_tx, dict):
        return nested_tx
    nested_tx_json = tx_data.get("tx_json")
    if isinstance(nested_tx_json, dict):
        return nested_tx_json
    nested_transaction = tx_data.get("transaction")
    if isinstance(nested_transaction, dict):
        return nested_transaction
    return tx_data


def build_proof_link(bundle_hash: str, tx_hash: str) -> dict:
    return {
        "bundle_hash": bundle_hash,
        "tx_hash": tx_hash,
    }


def _parse_first_memo(tx_payload: dict) -> str | None:
    memos_raw = tx_payload.get("Memos", [])
    if not (memos_raw and isinstance(memos_raw, list)):
        return None
    first_memo = memos_raw[0]
    memo_obj = first_memo.get("Memo", first_memo) if isinstance(first_memo, dict) else {}
    memo_data_hex = memo_obj.get("MemoData", "")
    if not memo_data_hex:
        return None
    # ``decode_memo_hex`` returns the decoded UTF-8 text or, on invalid hex /
    # invalid UTF-8, the original hex string – matching the prior behaviour
    # of this helper which fell back to ``memo_data_hex`` on exception.
    return decode_memo_hex(memo_data_hex)


def _tx_lookup_failed(tx_data: dict) -> bool:
    """Return ``True`` when the XRPL ``tx`` lookup did not return a transaction.

    The XRPL ``tx`` JSON-RPC method returns an ``error`` field (e.g.
    ``"txnNotFound"``) and ``status == "error"`` when the requested
    transaction could not be located on the ledger. Treat any of those
    signals – or a payload that lacks the basic ``TransactionType`` /
    ``hash`` markers of a real transaction – as "tx not found".
    """
    if not isinstance(tx_data, dict):
        return True
    if tx_data.get("error"):
        return True
    if str(tx_data.get("status", "")).lower() == "error":
        return True
    payload = _extract_tx_payload(tx_data)
    if not payload.get("TransactionType") and not payload.get("hash"):
        return True
    return False


def verify_settlement_by_hash(bundle_hash: str, tx_hash: str) -> SettlementVerifyByHashResponse:
    """Verify an XRPL settlement against a previously-issued permit bundle.

    The endpoint backing this service is ``POST /v1/settlement/verify``. The
    decision is ``SETTLED_COMPLIANT`` only when *all* of the following hold:

    * the transaction is found on the configured XRPL network,
    * the transaction is validated,
    * the transaction's first memo decodes to the supplied ``bundle_hash``,
    * a permit record exists in the database for ``bundle_hash``,
    * the transaction's ``Account`` matches the permit ``subject`` (or the
      optional ``constraints.expected_sender`` override when present),
    * the transaction amount is ``<=`` the permit's ``constraints.max_amount``,
    * the permit ``action`` is ``transfer`` (i.e. the on-ledger transaction is
      a ``Payment``).

    Otherwise ``SETTLEMENT_NON_COMPLIANT`` is returned together with reason
    codes describing each failed check.
    """
    permit_context = get_permit_context(bundle_hash)
    if permit_context is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "permit_not_found",
                "reason": "No persisted permit context found for bundle_hash",
                "reason_code": "PERMIT_CONTEXT_NOT_FOUND",
                "bundle_hash": bundle_hash,
            },
        )
    permit_bundle = permit_context.get("bundle") or {}
    permit_constraints = permit_bundle.get("constraints") or {}

    tx_data = fetch_xrpl_transaction(tx_hash)
    tx_payload = _extract_tx_payload(tx_data)

    reason_codes: list[str] = []
    constraints_verified: dict[str, bool] = {}
    compliant = True

    # Permit context was successfully loaded above; record that explicitly
    # at the head of the reason-code list so the artifact reflects every
    # gate that was evaluated, not just the failing ones.
    reason_codes.insert(0, "PERMIT_CONTEXT_FOUND")

    amount_info = normalize_xrpl_amount(tx_payload.get("Amount", {}))
    memo = _parse_first_memo(tx_payload)
    memo_bundle_hash = memo

    # -- bundle_hash / memo binding --
    # The XRPL transaction is expected to carry the permit ``bundle_hash``
    # as the first memo's ``MemoData``. Emit explicit reason codes so the
    # proof artifact records whether that binding was present and matched.
    decision_result = "SETTLED_COMPLIANT"
    if memo is None:
        memo_match = False
        reason_codes.append("BUNDLE_HASH_MEMO_MISSING")
    elif memo == bundle_hash:
        memo_match = True
        reason_codes.append("BUNDLE_HASH_MEMO_MATCHED")
    else:
        memo_match = False
        reason_codes.append("BUNDLE_HASH_MEMO_MISMATCH")
    constraints_verified["bundle_hash_memo_match"] = memo_match
    if not memo_match:
        decision_result = "SETTLEMENT_NON_COMPLIANT"

    # -- final settlement decision summary --
    if decision_result == "SETTLED_COMPLIANT":
        reason_codes.append("SETTLEMENT_VERIFIED")
    else:
        reason_codes.append("SETTLEMENT_VERIFICATION_FAILED")

    # 1. Transaction exists on XRPL.
    tx_found = not _tx_lookup_failed(tx_data)
    constraints_verified["tx_found"] = tx_found
    if tx_found:
        reason_codes.append("TX_FOUND")
    else:
        reason_codes.append("TX_NOT_FOUND")
        compliant = False

    # 2. Transaction is validated.
    tx_validated = bool(tx_data.get("validated") or tx_payload.get("validated"))
    constraints_verified["tx_validated"] = tx_validated
    if tx_validated:
        reason_codes.append("TX_VALIDATED")
    else:
        reason_codes.append("TX_NOT_VALIDATED")
        compliant = False

    # 3. Decoded memo contains the provided bundle_hash.
    memo = extract_bundle_hash_from_tx(tx_payload)
    if memo is None:
        bundle_hash_memo_match = False
        constraints_verified["bundle_hash_memo_match"] = False
        reason_codes.append("BUNDLE_HASH_MEMO_MISSING")
        compliant = False
    else:
        bundle_hash_memo_match = bundle_hash in memo
        constraints_verified["bundle_hash_memo_match"] = bundle_hash_memo_match
        if bundle_hash_memo_match:
            reason_codes.append("BUNDLE_HASH_MEMO_MATCH")
        else:
            reason_codes.append("BUNDLE_HASH_MEMO_MISMATCH")
            compliant = False

    # 4. Subject (or expected_sender override) matches the tx Account.
    expected_sender = permit_constraints.get("expected_sender") or permit_bundle.get("subject")
    tx_account = tx_payload.get("Account", "")
    if expected_sender:
        subject_match = tx_account == expected_sender
        constraints_verified["subject_match"] = subject_match
        if subject_match:
            reason_codes.append("SUBJECT_MATCH")
        else:
            reason_codes.append("SUBJECT_MISMATCH")
            compliant = False
    else:
        constraints_verified["subject_match"] = False
        reason_codes.append("PERMIT_SUBJECT_MISSING")
        compliant = False

    # 5. Amount within permit max_amount.
    amount_info = normalize_xrpl_amount(tx_payload.get("Amount", {}))
    try:
        tx_value = float(amount_info["value"])
    except (TypeError, ValueError):
        tx_value = 0.0
    max_amount = permit_constraints.get("max_amount")
    if max_amount is None:
        constraints_verified["amount_within_limit"] = False
        reason_codes.append("PERMIT_MAX_AMOUNT_MISSING")
        compliant = False
    else:
        try:
            amount_ok = tx_value <= float(max_amount)
        except (TypeError, ValueError):
            amount_ok = False
        constraints_verified["amount_within_limit"] = amount_ok
        if amount_ok:
            reason_codes.append("AMOUNT_WITHIN_LIMIT")
        else:
            reason_codes.append("AMOUNT_EXCEEDS_LIMIT")
            compliant = False

    # 6. Action is "transfer" (XRPL Payment).
    permit_action = permit_bundle.get("action")
    tx_type = tx_payload.get("TransactionType", "")
    action_match = permit_action == "transfer" and tx_type == "Payment"
    constraints_verified["action_match"] = action_match
    if action_match:
        reason_codes.append("ACTION_MATCH")
    else:
        reason_codes.append("ACTION_MISMATCH")
        compliant = False

    decision_result = "SETTLED_COMPLIANT" if compliant else "SETTLEMENT_NON_COMPLIANT"
    now = int(time.time())

    ledger_index = tx_data.get("ledger_index") or tx_data.get("inLedger")
    if ledger_index is None:
        ledger_index = tx_payload.get("ledger_index") or tx_payload.get("inLedger")

    permit_evidence = permit_bundle.get("compliance_evidence", [])
    permit_attestations = permit_bundle.get("attestations") or {}
    evaluation_context = {
        "bundle_hash": bundle_hash,
        "permit_context_used": True,
        "xrpl_network": config.XRPL_NETWORK,
        "tx_hash": tx_hash,
        "ledger_index": ledger_index,
        "validated": tx_validated,
        "tx_found": tx_found,
        "source_account": tx_account,
        "source": tx_account,
        "destination_account": tx_payload.get("Destination", ""),
        "destination": tx_payload.get("Destination", ""),
        "currency": amount_info["currency"],
        "amount": amount_info["value"],
        "issuer": amount_info["issuer"],
        "memo": memo,
        "memo_bundle_hash": memo_bundle_hash,
        "memo_match": memo_match,
        "expected_sender": expected_sender,
        "permit_action": permit_action,
        "tx_type": tx_type,
        "asset_classification": ASSET_CLASSIFICATION_REGULATED_STABLECOIN,
        "asset": amount_info["currency"],
        "jurisdiction": permit_constraints.get("jurisdiction", config.JURISDICTION),
        "kyc_verified": permit_constraints.get("kyc_verified", False),
        "sanctions_check": permit_constraints.get("sanctions_check", "unavailable"),
        "reserve_backed": permit_constraints.get("reserve_backed", False),
        "liquidity_verified": permit_constraints.get("liquidity_verified", False),
        "kyc_reference": permit_attestations.get("kyc_reference"),
        "kyc_destination_reference": permit_attestations.get("kyc_destination_reference"),
        "sanctions_reference": permit_attestations.get("sanctions_reference"),
        "reserve_reference": permit_attestations.get("reserve_reference"),
        "liquidity_reference": permit_attestations.get("liquidity_reference"),
        "policy_conditions": {
            "jurisdiction": permit_constraints.get("jurisdiction", config.JURISDICTION),
            "kyc_verified": permit_constraints.get("kyc_verified", False),
            "sanctions": permit_constraints.get("sanctions_check", "unavailable"),
            "reserve_backed": permit_constraints.get("reserve_backed", False),
            "liquidity_verified": permit_constraints.get("liquidity_verified", False),
        },
        "compliance_evidence": permit_evidence,
        "constraints_verified": constraints_verified,
    }
    evaluation_context["permit_issued_at"] = permit_context["issued_at"]
    evaluation_context["permit_bundle"] = permit_context["bundle"]
    evaluation_context["permit_proof_artifact"] = permit_context["proof_artifact"]

    anchor_metadata: dict = {
        "network": "xrpl-testnet",
        "tx_hash": tx_hash,
        "verified_at": now,
    }
    if ledger_index is not None:
        anchor_metadata["ledger_index"] = ledger_index

    proof_artifact = build_proof_artifact(
        module="CompliGate",
        entity_id=tx_hash,
        rule_version_used=config.POLICY_VERSION,
        decision_result=decision_result,
        evaluation_context=evaluation_context,
        reason_codes=reason_codes,
        timestamp=now,
        bundle_hash=bundle_hash,
        anchor_metadata=anchor_metadata,
    )

    return SettlementVerifyByHashResponse(
        decision_result=decision_result,
        reason_codes=reason_codes,
        proof_artifact=proof_artifact,
    )
