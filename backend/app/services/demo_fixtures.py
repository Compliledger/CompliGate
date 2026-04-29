"""Demo scenario fixtures for the CompliGate compliance flow.

These fixtures provide deterministic inputs for the four canonical demo
scenarios used to exercise the end-to-end compliance decision pipeline
without contacting any live provider:

* ``fully_compliant``    -> COMPLIANT decision
* ``liquidity_risk``     -> NON_COMPLIANT (INSUFFICIENT_HQLA)
* ``sanctions_hit``      -> NON_COMPLIANT (SANCTIONED_COUNTERPARTY)
* ``reserve_shortfall``  -> NON_COMPLIANT (RESERVE_RATIO_BELOW_1_TO_1)

Each fixture exposes the *actual* underlying balance-sheet figures
(``total_reserves``, ``total_liabilities``, ``hqla_assets``) the engine
would normally derive its ratios from, alongside the pre-computed
``reserve_ratio`` and ``liquidity_ratio`` for convenience. Concrete
amounts make the fixtures suitable for both ratio-based checks and any
downstream consumer that needs the raw figures (proof artifacts, audit
logs, UI displays, …).

The expected decision and (where applicable) reason code are part of
the fixture so tests and demo runners can assert on the final outcome
without re-implementing engine logic.
"""

from __future__ import annotations

from typing import Final, Mapping

# ---------------------------------------------------------------------------
# Decision / reason code vocabulary
# ---------------------------------------------------------------------------

#: Final decision values surfaced by the compliance engine.
DECISION_COMPLIANT: Final[str] = "COMPLIANT"
DECISION_NON_COMPLIANT: Final[str] = "NON_COMPLIANT"

#: Sanctions screening outcomes used by the demo scenarios.
SANCTIONS_STATUS_CLEAN: Final[str] = "clean"
SANCTIONS_STATUS_SANCTIONED: Final[str] = "sanctioned"

#: Machine-readable reason codes returned alongside a NON_COMPLIANT
#: decision. Kept as module-level constants so callers and tests can
#: reference them symbolically.
REASON_INSUFFICIENT_HQLA: Final[str] = "INSUFFICIENT_HQLA"
REASON_SANCTIONED_COUNTERPARTY: Final[str] = "SANCTIONED_COUNTERPARTY"
REASON_RESERVE_RATIO_BELOW_1_TO_1: Final[str] = "RESERVE_RATIO_BELOW_1_TO_1"


# ---------------------------------------------------------------------------
# Scenario identifiers
# ---------------------------------------------------------------------------

SCENARIO_FULLY_COMPLIANT: Final[str] = "fully_compliant"
SCENARIO_LIQUIDITY_RISK: Final[str] = "liquidity_risk"
SCENARIO_SANCTIONS_HIT: Final[str] = "sanctions_hit"
SCENARIO_RESERVE_SHORTFALL: Final[str] = "reserve_shortfall"

#: Ordered tuple of every supported demo scenario identifier.
SCENARIOS: Final[tuple[str, ...]] = (
    SCENARIO_FULLY_COMPLIANT,
    SCENARIO_LIQUIDITY_RISK,
    SCENARIO_SANCTIONS_HIT,
    SCENARIO_RESERVE_SHORTFALL,
)


# ---------------------------------------------------------------------------
# Underlying balance-sheet figures
# ---------------------------------------------------------------------------
#
# A common ``total_liabilities`` baseline keeps the scenarios easy to
# compare side-by-side: only the numerator (reserves / HQLA) changes
# between scenarios, which makes the resulting ratios easy to reason
# about.
#
#   reserve_ratio   = total_reserves / total_liabilities
#   liquidity_ratio = hqla_assets    / total_liabilities

_TOTAL_LIABILITIES: Final[float] = 1_000_000.00


def _ratios(total_reserves: float, hqla_assets: float) -> dict[str, float]:
    """Return the (reserve_ratio, liquidity_ratio) pair for the figures."""
    return {
        "total_reserves": total_reserves,
        "total_liabilities": _TOTAL_LIABILITIES,
        "hqla_assets": hqla_assets,
        "reserve_ratio": round(total_reserves / _TOTAL_LIABILITIES, 4),
        "liquidity_ratio": round(hqla_assets / _TOTAL_LIABILITIES, 4),
    }


# ---------------------------------------------------------------------------
# Demo scenario fixtures
# ---------------------------------------------------------------------------

DEMO_SCENARIOS: Final[dict[str, dict]] = {
    SCENARIO_FULLY_COMPLIANT: {
        "scenario": SCENARIO_FULLY_COMPLIANT,
        "description": (
            "Reserves and HQLA both healthy, counterparty clean -> "
            "engine should return COMPLIANT."
        ),
        # 1,020,000 / 1,000,000 = 1.02   ;   950,000 / 1,000,000 = 0.95
        "reserves": _ratios(total_reserves=1_020_000.00, hqla_assets=950_000.00),
        "sanctions": {
            "sanctions_status": SANCTIONS_STATUS_CLEAN,
            "counterparty_id": "CP-CLEAN-001",
        },
        "expected": {
            "final_decision": DECISION_COMPLIANT,
            "reason": None,
        },
    },
    SCENARIO_LIQUIDITY_RISK: {
        "scenario": SCENARIO_LIQUIDITY_RISK,
        "description": (
            "Reserves cover liabilities 1.02x but HQLA only covers 60% "
            "of liabilities -> NON_COMPLIANT for INSUFFICIENT_HQLA."
        ),
        # 1,020,000 / 1,000,000 = 1.02   ;   600,000 / 1,000,000 = 0.60
        "reserves": _ratios(total_reserves=1_020_000.00, hqla_assets=600_000.00),
        "sanctions": {
            "sanctions_status": SANCTIONS_STATUS_CLEAN,
            "counterparty_id": "CP-CLEAN-002",
        },
        "expected": {
            "final_decision": DECISION_NON_COMPLIANT,
            "reason": REASON_INSUFFICIENT_HQLA,
        },
    },
    SCENARIO_SANCTIONS_HIT: {
        "scenario": SCENARIO_SANCTIONS_HIT,
        "description": (
            "Balance-sheet metrics are healthy but the counterparty "
            "is on a sanctions list -> NON_COMPLIANT for "
            "SANCTIONED_COUNTERPARTY."
        ),
        # 1,020,000 / 1,000,000 = 1.02   ;   950,000 / 1,000,000 = 0.95
        "reserves": _ratios(total_reserves=1_020_000.00, hqla_assets=950_000.00),
        "sanctions": {
            "sanctions_status": SANCTIONS_STATUS_SANCTIONED,
            "counterparty_id": "CP-SANCTIONED-007",
            "sanctions_list": "OFAC_SDN",
        },
        "expected": {
            "final_decision": DECISION_NON_COMPLIANT,
            "reason": REASON_SANCTIONED_COUNTERPARTY,
        },
    },
    SCENARIO_RESERVE_SHORTFALL: {
        "scenario": SCENARIO_RESERVE_SHORTFALL,
        "description": (
            "Reserves only cover 85% of liabilities -> hard fail with "
            "RESERVE_RATIO_BELOW_1_TO_1."
        ),
        # 850,000 / 1,000,000 = 0.85   ;   950,000 / 1,000,000 = 0.95
        "reserves": _ratios(total_reserves=850_000.00, hqla_assets=950_000.00),
        "sanctions": {
            "sanctions_status": SANCTIONS_STATUS_CLEAN,
            "counterparty_id": "CP-CLEAN-004",
        },
        "expected": {
            "final_decision": DECISION_NON_COMPLIANT,
            "reason": REASON_RESERVE_RATIO_BELOW_1_TO_1,
        },
    },
}


def get_demo_scenario(scenario: str) -> Mapping[str, object]:
    """Return the fixture mapping for ``scenario``.

    Args:
        scenario: One of :data:`SCENARIOS`.

    Raises:
        KeyError: when ``scenario`` is not a known demo scenario.
    """
    if scenario not in DEMO_SCENARIOS:
        raise KeyError(scenario)
    return DEMO_SCENARIOS[scenario]


def list_demo_scenarios() -> tuple[str, ...]:
    """Return the tuple of supported demo scenario identifiers."""
    return SCENARIOS
