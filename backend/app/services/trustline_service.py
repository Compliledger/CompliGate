from __future__ import annotations

from fastapi import HTTPException

from app.core import config


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


def validate_trustline(address: str, issuer: str, currency: str) -> dict:
    from app.services.xrpl_service import fetch_account_lines

    lines = fetch_account_lines(address)
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


def validate_trustline_check(address: str, issuer: str, currency: str) -> dict:
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

    result = validate_trustline(address, issuer, currency)
    result["address"] = address
    return result
