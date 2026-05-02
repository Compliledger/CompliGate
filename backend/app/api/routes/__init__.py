from __future__ import annotations

from fastapi import APIRouter

from app.api.routes.health import router as health_router
from app.api.routes.permit import router as permit_router
from app.api.routes.settlement import router as settlement_router
from app.api.routes.verify import router as verify_router
from app.api.routes.xrpl import router as xrpl_router

ROUTERS: tuple[APIRouter, ...] = (
    health_router,
    permit_router,
    verify_router,
    xrpl_router,
    settlement_router,
)
