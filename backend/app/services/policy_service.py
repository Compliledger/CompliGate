from __future__ import annotations

from fastapi import HTTPException

from app.core import config

SUPPORTED_ACTIONS = {"transfer", "trustset"}
MAX_AMOUNT = 5_000_000
REASON_CODES = ["kyc_verified", "policy_compliant", "amount_within_limits"]
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


def evaluate_constraints(
    action: str,
    amount: float | int | None,
    counterparty: str | None,
) -> list[str]:
    _ = counterparty
    if action not in SUPPORTED_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_action",
                "reason": f"action '{action}' is not supported; allowed: {sorted(SUPPORTED_ACTIONS)}",
            },
        )
    if amount is not None and amount > MAX_AMOUNT:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "transaction_not_allowed",
                "reason": "amount exceeds policy maximum",
            },
        )
    reason_codes: list[str] = []
    reason_codes.append("KYC_VERIFIED")
    reason_codes.append("SANCTIONS_PASSED")
    reason_codes.append("RESERVE_BACKED")
    reason_codes.append("LIQUIDITY_VERIFIED")
    reason_codes.append("ISSUER_CONTROLS_ACTIVE")
    if amount is not None:
        reason_codes.append("AMOUNT_WITHIN_LIMIT")
    return reason_codes
