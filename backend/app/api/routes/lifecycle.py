"""POST /lifecycle/run-demo route.

Demo-focused endpoint that runs the full thin-MVP CompliStack lifecycle
end-to-end against a fixture-driven scenario and returns the assembled
universal CompliProof artifact.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.auth import require_request_auth
from app.core.logging import get_logger
from app.services.lifecycle import SUPPORTED_SCENARIOS, run_demo_lifecycle

router = APIRouter(dependencies=[Depends(require_request_auth)])
logger = get_logger("main")


# Pydantic Literal validation rejects unknown scenarios at the framework
# layer so the handler itself can stay focused on the demo flow.
ScenarioName = Literal[
    "fully_compliant",
    "liquidity_risk",
    "sanctions_hit",
    "reserve_shortfall",
]


class RunDemoRequest(BaseModel):
    scenario: ScenarioName


@router.post("/lifecycle/run-demo")
def run_demo_lifecycle_route(req: RunDemoRequest) -> dict:
    # Defensive guard: keeps the implementation contract explicit even
    # though Pydantic Literal validation already rejects unknown values.
    if req.scenario not in SUPPORTED_SCENARIOS:  # pragma: no cover - safety net
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_scenario",
                "reason": f"scenario must be one of {list(SUPPORTED_SCENARIOS)}",
            },
        )

    result = run_demo_lifecycle(req.scenario)
    logger.info(
        "lifecycle_run_demo scenario=%s status=%s proof_hash=%s",
        result["scenario"],
        result["lifecycle_status"],
        result["proof_hash"],
    )
    return result
