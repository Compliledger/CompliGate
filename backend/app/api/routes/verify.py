from __future__ import annotations

from fastapi import APIRouter

from app.models.permit import VerifyRequest
from app.services.permit_service import verify_permit as verify_permit_service

router = APIRouter()


@router.post("/v1/verify")
def verify_permit_route(req: VerifyRequest):
    return verify_permit_service(req)
