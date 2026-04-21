from __future__ import annotations

from fastapi import Header, HTTPException

from app.core import config


def _extract_auth_key(x_api_key: str | None, authorization: str | None) -> str | None:
    if x_api_key:
        return x_api_key.strip()
    if not authorization:
        return None
    parts = authorization.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return authorization.strip()


def require_request_auth(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> None:
    allowed_keys = config.AUTH_API_KEYS
    if not allowed_keys:
        return
    provided = _extract_auth_key(x_api_key, authorization)
    if provided and provided in allowed_keys:
        return
    raise HTTPException(
        status_code=401,
        detail={"error": "unauthorized", "reason": "Missing or invalid API key"},
    )
