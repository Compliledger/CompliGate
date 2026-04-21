from __future__ import annotations

import requests as http_requests
from fastapi import HTTPException

from app.core import config


def fetch_account_lines(address: str) -> list[dict]:
    payload = {
        "method": "account_lines",
        "params": [{"account": address}],
    }
    try:
        resp = http_requests.post(config.XRPL_RPC_URL, json=payload, timeout=10)
        resp.raise_for_status()
        result = resp.json()
        if "result" in result:
            return result["result"].get("lines", [])
        return result.get("lines", [])
    except http_requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": "xrpl_rpc_failed", "reason": str(exc)},
        ) from exc


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
