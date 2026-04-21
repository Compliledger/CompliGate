from __future__ import annotations

from fastapi import APIRouter

from app.core.security import get_public_key_payload

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/public-key")
def public_key():
    return get_public_key_payload()
