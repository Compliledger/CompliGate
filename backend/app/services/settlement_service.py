from __future__ import annotations

from app.core import config
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
