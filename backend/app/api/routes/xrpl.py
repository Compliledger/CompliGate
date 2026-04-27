from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.auth import require_request_auth
from app.core import config
from app.models.xrpl import TrustlineCheckRequest, XRPLPaymentRequest, XRPLPaymentResponse
from app.services.trustline_service import enforce_destination_trustline, get_account_trustlines_summary, validate_trustline_check
from app.services.xrpl_service import fetch_account_lines, get_xrpl_health_status, lookup_xrpl_transaction, submit_xrpl_payment

router = APIRouter()


@router.get("/v1/xrpl/health")
def xrpl_health():
    return get_xrpl_health_status()


@router.get("/v1/xrpl/tx/{tx_hash}", dependencies=[Depends(require_request_auth)])
def xrpl_tx_lookup(tx_hash: str):
    return lookup_xrpl_transaction(tx_hash)


@router.get("/v1/xrpl/account/{address}/trustlines", dependencies=[Depends(require_request_auth)])
def xrpl_account_trustlines(address: str):
    return get_account_trustlines_summary(address, fetch_account_lines)


@router.post("/v1/xrpl/trustline/check", dependencies=[Depends(require_request_auth)])
def xrpl_trustline_check(req: TrustlineCheckRequest):
    return validate_trustline_check(req.address, config.RLUSD_ISSUER, config.RLUSD_CURRENCY, fetch_account_lines)


@router.post("/v1/xrpl/payment", response_model=XRPLPaymentResponse, dependencies=[Depends(require_request_auth)])
def xrpl_payment(req: XRPLPaymentRequest):
    return submit_xrpl_payment(req)
