from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.health import router as health_router
from app.api.routes.permit import router as permit_router
from app.api.routes.settlement import router as settlement_router
from app.api.routes.verify import router as verify_router
from app.api.routes.xrpl import router as xrpl_router
from app.core import config
from app.core.logging import configure_logging
from app.services.permit_service import get_recent_permit_context as _get_recent_permit_context
from app.services.permit_service import store_recent_permit_context as _store_recent_permit_context
from app.services.policy_service import ASSET_CLASSIFICATION_REGULATED_STABLECOIN, MAX_AMOUNT, REASON_CODES, SUPPORTED_ACTIONS, evaluate_constraints, evaluate_eligibility, evaluate_governance, validate_action, validate_amount, validate_subject
from app.services.proof_service import enrich_proof_artifact_with_anchor, random_hex
from app.services.settlement_service import _evaluate_settlement_constraints, build_proof_link, fetch_xrpl_transaction, verify_settlement_against_permit
from app.services.trustline_service import check_rlusd_trustline, validate_trustline
from app.services.xrpl_service import _XRPL_SDK_AVAILABLE, get_account_info, get_account_lines, get_demo_wallet, get_transaction, get_xrpl_client, is_rlusd_payment, normalize_amount, normalize_xrpl_amount

configure_logging()

app = FastAPI(title=config.APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in config.CORS_ORIGINS.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(permit_router)
app.include_router(verify_router)
app.include_router(xrpl_router)
app.include_router(settlement_router)

# compatibility exports
POLICY_VERSION = config.POLICY_VERSION
JURISDICTION = config.JURISDICTION
CURRENCY = config.CURRENCY
ISSUER_ADDRESS = config.ISSUER_ADDRESS
XRPL_RPC_URL = config.XRPL_RPC_URL
XRPL_NETWORK = config.XRPL_NETWORK
RLUSD_ISSUER = config.RLUSD_ISSUER
RLUSD_CURRENCY = config.RLUSD_CURRENCY
XRPL_DEMO_WALLET_SEED = config.XRPL_DEMO_WALLET_SEED
XRPL_REQUIRE_TRUSTLINE = config.XRPL_REQUIRE_TRUSTLINE
APP_NAME = config.APP_NAME
