from __future__ import annotations

import base64
import time

from fastapi import APIRouter

from app.core.logging import get_logger
from app.core.security import VERIFY_KEY
from app.models.permit import VerifyRequest
from app.utils.canonical_json import canonical_json
from app.utils.hashing import proof_hash

router = APIRouter()
logger = get_logger("main")


@router.post("/v1/verify")
def verify_permit(req: VerifyRequest):
    try:
        canonical = canonical_json(req.bundle).encode("utf-8")
        sig_bytes = base64.b64decode(req.signature)
        VERIFY_KEY.verify(canonical, sig_bytes)
        signature_valid = True
    except Exception:
        signature_valid = False

    now = int(time.time())
    exp = req.bundle.get("exp", 0)
    not_expired = now < exp

    subject = req.bundle.get("subject")
    logger.info(
        "permit_verified subject=%s signature_valid=%s not_expired=%s",
        subject,
        signature_valid,
        not_expired,
    )

    return {
        "signature_valid": signature_valid,
        "not_expired": not_expired,
        "subject": req.bundle.get("subject"),
        "policy_version": req.bundle.get("policy", {}).get("version"),
        "action": req.bundle.get("action"),
        "bundle_hash": proof_hash(req.bundle),
        "constraints": req.bundle.get("constraints", {}),
    }
