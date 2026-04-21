from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.auth import require_request_auth
from app.models.permit import VerifyRequest
from app.services.permit_service import verify_permit_logic as verify_service

router = APIRouter(dependencies=[Depends(require_request_auth)])


@router.post("/v1/verify")
def verify_permit(req: VerifyRequest):
    return verify_service(req)
