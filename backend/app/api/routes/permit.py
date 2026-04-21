from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.auth import require_request_auth
from app.db.session import get_db
from app.models.permit import PermitRequest, PermitResponse
from app.models.proof import ProofArtifact
from app.services.permit_service import create_permit
from app.services.proof_service import create_proof_artifact_from_permit_req

router = APIRouter(dependencies=[Depends(require_request_auth)])


@router.post("/v1/permit", response_model=PermitResponse)
def create_permit_route(req: PermitRequest, db: Session | None = Depends(get_db)):
    return create_permit(req, db=db)


@router.post("/v1/proof-artifact", response_model=ProofArtifact)
def create_proof_artifact_route(req: PermitRequest):
    return create_proof_artifact_from_permit_req(req)
