from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from app.core import config
from app.services.compliance import ComplianceEvaluation, evaluate_compliance

SUPPORTED_ACTIONS = {"transfer", "trustset"}
MAX_AMOUNT = 5_000_000
ASSET_CLASSIFICATION_REGULATED_STABLECOIN = "regulated_stablecoin"


def validate_subject(subject: str) -> None:
    if not isinstance(subject, str):
        raise HTTPException(status_code=400, detail={"error": "invalid_subject", "reason": "subject must be a string"})
    if not subject.startswith("r"):
        raise HTTPException(status_code=400, detail={"error": "invalid_subject", "reason": "subject must start with 'r'"})
    if not (25 <= len(subject) <= 35):
        raise HTTPException(status_code=400, detail={"error": "invalid_subject", "reason": "subject length must be 25-35 chars"})


def validate_action(action: str) -> None:
    if action not in SUPPORTED_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_action",
                "reason": f"action '{action}' is not supported; allowed: {sorted(SUPPORTED_ACTIONS)}",
            },
        )


def validate_amount(amount: float | int | None) -> None:
    if amount is not None and amount > MAX_AMOUNT:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "transaction_not_allowed",
                "reason": "amount exceeds policy maximum",
            },
        )


def evaluate_governance() -> dict:
    return {
        "policy_version": config.POLICY_VERSION,
        "jurisdiction": config.JURISDICTION,
        "state_status": "active",
        "state_ref": "gov_demo_001",
    }


def evaluate_eligibility() -> dict:
    return {
        "participant_eligible": True,
        "asset_admitted": True,
        "admission_ref": "admission_demo_001",
    }


def evaluate_permit_policy(
    *,
    subject: str,
    action: str,
    amount: float | int | None,
    counterparty: str | None,
    asset: dict[str, Any] | None = None,
    kyc_assertion: dict[str, Any] | None = None,
    reserve_attestation: dict[str, Any] | None = None,
) -> dict:
    """Evaluate the full permit policy and return a structured decision.

    The compliance portion is delegated to provider-backed checks. If any
    provider denies or is unavailable, the overall decision is ``deny``
    with explicit reason codes so the caller can surface a fail-closed
    response that is fully traceable to provider evidence.
    """
    validate_action(action)
    validate_amount(amount)

    governance = evaluate_governance()
    eligibility = evaluate_eligibility()
    compliance: ComplianceEvaluation = evaluate_compliance(
        subject=subject,
        action=action,
        amount=amount,
        counterparty=counterparty,
        asset=asset,
        kyc_assertion=kyc_assertion,
        reserve_attestation=reserve_attestation,
    )

    reason_codes: list[str] = []
    decision = "allow"

    if governance["state_status"] == "active":
        reason_codes.append("POLICY_ACTIVE")
    else:
        reason_codes.append("POLICY_INACTIVE")
        decision = "deny"

    if eligibility["participant_eligible"]:
        reason_codes.append("PARTICIPANT_ELIGIBLE")
    else:
        reason_codes.append("PARTICIPANT_NOT_ELIGIBLE")
        decision = "deny"

    if eligibility["asset_admitted"]:
        reason_codes.append("ASSET_ADMITTED")
    else:
        reason_codes.append("ASSET_NOT_ADMITTED")
        decision = "deny"

    reason_codes.extend(compliance.reason_codes)
    if not compliance.allowed:
        decision = "deny"

    if amount is not None:
        reason_codes.append("AMOUNT_WITHIN_LIMIT")

    return {
        "decision_result": decision,
        "reason_codes": reason_codes,
        "governance": governance,
        "eligibility": eligibility,
        "compliance": compliance,
    }
