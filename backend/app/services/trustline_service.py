from __future__ import annotations

from collections.abc import Callable

from fastapi import HTTPException

from app.core import config
from app.core.logging import get_logger

logger = get_logger("main")


def check_rlusd_trustline(lines: list[dict]) -> dict:
    for line in lines:
        line_currency = line.get("currency", "")
        line_issuer = line.get("account", "")

        currency_match = line_currency == config.RLUSD_CURRENCY
        issuer_match = (not config.RLUSD_ISSUER) or (line_issuer == config.RLUSD_ISSUER)

        if currency_match and issuer_match:
            return {
                "has_trustline": True,
                "currency": line_currency,
                "issuer": line_issuer,
                "limit": line.get("limit", "0"),
                "balance": line.get("balance", "0"),
            }

    return {
        "has_trustline": False,
        "currency": config.RLUSD_CURRENCY,
        "issuer": config.RLUSD_ISSUER,
        "limit": "0",
        "balance": "0",
    }


def _validate_trustline_lines(lines: list[dict], issuer: str, currency: str) -> dict:
    for line in lines:
        line_currency = line.get("currency", "")
        line_issuer = line.get("account", "")
        currency_match = line_currency == currency
        issuer_match = (not issuer) or (line_issuer == issuer)
        if currency_match and issuer_match:
            return {
                "trustline_exists": True,
                "issuer": line_issuer,
                "currency": line_currency,
                "raw_lines_checked": len(lines),
            }
    return {
        "trustline_exists": False,
        "issuer": issuer,
        "currency": currency,
        "raw_lines_checked": len(lines),
    }


def validate_trustline(
    address: str,
    issuer: str,
    currency: str,
    fetch_account_lines_func: Callable[[str], list[dict]],
) -> dict:
    lines = fetch_account_lines_func(address)
    return _validate_trustline_lines(lines, issuer, currency)


def validate_trustline_check(
    address: str,
    issuer: str,
    currency: str,
    fetch_account_lines_func: Callable[[str], list[dict]],
) -> dict:
    if not address.startswith("r"):
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_address", "reason": "address must be a string starting with 'r'"},
        )
    if not (25 <= len(address) <= 35):
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_address", "reason": "address length must be 25-35 chars"},
        )
    if not config.XRPL_RPC_URL:
        raise HTTPException(
            status_code=400,
            detail={"error": "xrpl_not_configured", "reason": "XRPL_RPC_URL is not configured"},
        )

    result = validate_trustline(address, issuer, currency, fetch_account_lines_func)
    result["address"] = address
    return result


def get_account_trustlines_summary(
    address: str,
    fetch_account_lines_func: Callable[[str], list[dict]],
) -> dict:
    if not config.XRPL_RPC_URL:
        raise HTTPException(
            status_code=400,
            detail={"error": "xrpl_not_configured", "reason": "XRPL_RPC_URL is not configured"},
        )

    lines = fetch_account_lines_func(address)
    rlusd_check = check_rlusd_trustline(lines)

    logger.info(
        "xrpl_trustline_check address=%s has_rlusd_trustline=%s",
        address,
        rlusd_check["has_trustline"],
    )

    return {
        "address": address,
        "network": config.XRPL_NETWORK,
        "trustline_count": len(lines),
        "rlusd_trustline": rlusd_check,
        "lines": lines,
    }


def enforce_destination_trustline(
    destination: str,
    issuer: str,
    currency: str,
    fetch_account_lines_func: Callable[[str], list[dict]],
) -> None:
    if not config.XRPL_REQUIRE_TRUSTLINE:
        return

    trustline_result = validate_trustline(destination, issuer, currency, fetch_account_lines_func)
    if trustline_result.get("trustline_exists", False):
        return

    reason_codes = ["TRUSTLINE_REQUIRED", "TRUSTLINE_NOT_SATISFIED"]
    raise HTTPException(
        status_code=400,
        detail={
            "error": "trustline_required",
            "reason": "destination must have trustline for configured RLUSD issuer/currency",
            "reason_codes": reason_codes,
            "destination": destination,
            "issuer": issuer,
            "currency": currency,
            "raw_lines_checked": trustline_result.get("raw_lines_checked", 0),
        },
    )
