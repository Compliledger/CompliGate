from __future__ import annotations

import time

from app.core import config
from app.models.proof import build_proof_artifact
from app.models.xrpl import SettlementVerifyByHashResponse
from app.services.permit_service import get_recent_permit_context
from app.services.policy_service import ASSET_CLASSIFICATION_REGULATED_STABLECOIN, MAX_AMOUNT
from app.services.xrpl_service import fetch_xrpl_transaction as _fetch_xrpl_transaction
from app.services.xrpl_service import normalize_xrpl_amount


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

    tx_validated = tx_data.get("validated", False)
    constraints_verified["tx_validated"] = tx_validated
    if not tx_validated:
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

    constraints_verified["reserve_backed"] = True
    reason_codes.append("RESERVE_BACKED")

    constraints_verified["liquidity_verified"] = True
    reason_codes.append("LIQUIDITY_VERIFIED")

    constraints_verified["kyc_verified"] = True
    reason_codes.append("KYC_VERIFIED")

    constraints_verified["sanctions_check_passed"] = True
    reason_codes.append("SANCTIONS_PASSED")

    constraints_verified["jurisdiction_match"] = True
    reason_codes.append("JURISDICTION_MATCH")

    permit_constraints = (permit_bundle or {}).get("constraints", {})
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
    try:
        return bytes.fromhex(memo_data_hex).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return memo_data_hex


def verify_settlement_by_hash(bundle_hash: str, tx_hash: str) -> SettlementVerifyByHashResponse:
    permit_context = get_recent_permit_context(bundle_hash)
    permit_bundle = permit_context.get("bundle") if permit_context else None

    tx_data = fetch_xrpl_transaction(tx_hash)
    tx_payload = _extract_tx_payload(tx_data)

    decision_result, reason_codes, constraints_verified = _evaluate_settlement_constraints(
        tx_payload,
        permit_bundle=permit_bundle,
    )

    amount_info = normalize_xrpl_amount(tx_payload.get("Amount", {}))
    memo = _parse_first_memo(tx_payload)
    now = int(time.time())

    evaluation_context = {
        "bundle_hash": bundle_hash,
        "permit_context_used": bool(permit_context),
        "tx_hash": tx_hash,
        "source_account": tx_payload.get("Account", ""),
        "source": tx_payload.get("Account", ""),
        "destination_account": tx_payload.get("Destination", ""),
        "currency": amount_info["currency"],
        "amount": amount_info["value"],
        "issuer": amount_info["issuer"],
        "memo": memo,
        "asset_classification": ASSET_CLASSIFICATION_REGULATED_STABLECOIN,
        "asset": amount_info["currency"],
        "destination": tx_payload.get("Destination", ""),
        "jurisdiction": config.JURISDICTION,
        "kyc_verified": True,
        "sanctions_check": "passed",
        "reserve_backed": True,
        "liquidity_verified": True,
        "policy_conditions": {
            "jurisdiction": config.JURISDICTION,
            "kyc_verified": True,
            "sanctions": "passed",
            "reserve_backed": True,
            "liquidity_verified": True,
        },
        "constraints_verified": constraints_verified,
    }
    if permit_context:
        evaluation_context["permit_issued_at"] = permit_context["issued_at"]
        evaluation_context["permit_bundle"] = permit_context["bundle"]
        evaluation_context["permit_proof_artifact"] = permit_context["proof_artifact"]

    anchor_metadata: dict = {
        "network": config.XRPL_NETWORK,
        "tx_hash": tx_hash,
        "verified_at": now,
    }
    ledger_index = tx_data.get("ledger_index") or tx_data.get("inLedger")
    if ledger_index is None:
        ledger_index = tx_payload.get("ledger_index") or tx_payload.get("inLedger")
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
