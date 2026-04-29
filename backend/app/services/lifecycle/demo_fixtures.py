"""Fixture data for the four thin-MVP lifecycle demo scenarios.

The demo lifecycle is intentionally driven by static fixtures rather
than live provider calls so the ``/lifecycle/run-demo`` endpoint is
deterministic and reliable for showcase / smoke-test purposes.
"""

from __future__ import annotations

from typing import Final

# Supported demo scenario identifiers. Kept as a tuple so it can be
# safely iterated and exposed via the API for validation messages.
SCENARIOS: Final[tuple[str, ...]] = (
    "fully_compliant",
    "liquidity_risk",
    "sanctions_hit",
    "reserve_shortfall",
)


# Each fixture describes the inputs needed by every stub module so the
# demo flow is self-contained. Values are chosen to drive a specific
# decision per scenario:
#
#   * ``fully_compliant``    -> every module PASS
#   * ``liquidity_risk``     -> SolvencyProof + CompliGuard CONDITIONAL
#   * ``sanctions_hit``      -> CompliGate FAIL on sanctions hit
#   * ``reserve_shortfall``  -> SolvencyProof FAIL on reserve shortfall
DEMO_FIXTURES: Final[dict[str, dict]] = {
    "fully_compliant": {
        "subject": {
            "asset_id": "ASSET-RLUSD-001",
            "issuer_id": "ISSUER-ACME-001",
            "transaction_id": "TX-DEMO-FC-0001",
        },
        "issuer": {
            "issuer_id": "ISSUER-ACME-001",
            "name": "Acme Regulated Issuer",
            "jurisdiction": "US",
            "licensed": True,
            "registry_status": "active",
        },
        "token": {
            "asset_id": "ASSET-RLUSD-001",
            "symbol": "RLUSD",
            "intended_classification": "regulated_stablecoin",
            "fiat_backed": True,
        },
        "reserves": {
            "reserve_ratio": 1.05,
            "liquidity_ratio": 0.40,
            "attestation_id": "ATT-FC-2026-001",
        },
        "transaction": {
            "transaction_id": "TX-DEMO-FC-0001",
            "amount": 1000.0,
            "currency": "RLUSD",
            "counterparty_id": "CP-CLEAN-001",
            "sanctions_hit": False,
            "kyc_status": "verified",
        },
        "risk_signals": {
            "volatility": "low",
            "concentration": "low",
            "liquidity_pressure": "normal",
        },
        "settlement": {
            "settlement_id": "STL-DEMO-FC-0001",
            "rail": "xrpl",
            "preconditions_met": True,
            "atomic": True,
        },
    },
    "liquidity_risk": {
        "subject": {
            "asset_id": "ASSET-RLUSD-002",
            "issuer_id": "ISSUER-ACME-001",
            "transaction_id": "TX-DEMO-LR-0001",
        },
        "issuer": {
            "issuer_id": "ISSUER-ACME-001",
            "name": "Acme Regulated Issuer",
            "jurisdiction": "US",
            "licensed": True,
            "registry_status": "active",
        },
        "token": {
            "asset_id": "ASSET-RLUSD-002",
            "symbol": "RLUSD",
            "intended_classification": "regulated_stablecoin",
            "fiat_backed": True,
        },
        "reserves": {
            # Reserves still cover liabilities, but liquid buffer is thin.
            "reserve_ratio": 1.01,
            "liquidity_ratio": 0.08,
            "attestation_id": "ATT-LR-2026-001",
        },
        "transaction": {
            "transaction_id": "TX-DEMO-LR-0001",
            "amount": 750.0,
            "currency": "RLUSD",
            "counterparty_id": "CP-CLEAN-002",
            "sanctions_hit": False,
            "kyc_status": "verified",
        },
        "risk_signals": {
            "volatility": "elevated",
            "concentration": "medium",
            "liquidity_pressure": "elevated",
        },
        "settlement": {
            "settlement_id": "STL-DEMO-LR-0001",
            "rail": "xrpl",
            "preconditions_met": True,
            "atomic": True,
        },
    },
    "sanctions_hit": {
        "subject": {
            "asset_id": "ASSET-RLUSD-003",
            "issuer_id": "ISSUER-ACME-001",
            "transaction_id": "TX-DEMO-SH-0001",
        },
        "issuer": {
            "issuer_id": "ISSUER-ACME-001",
            "name": "Acme Regulated Issuer",
            "jurisdiction": "US",
            "licensed": True,
            "registry_status": "active",
        },
        "token": {
            "asset_id": "ASSET-RLUSD-003",
            "symbol": "RLUSD",
            "intended_classification": "regulated_stablecoin",
            "fiat_backed": True,
        },
        "reserves": {
            "reserve_ratio": 1.05,
            "liquidity_ratio": 0.40,
            "attestation_id": "ATT-SH-2026-001",
        },
        "transaction": {
            "transaction_id": "TX-DEMO-SH-0001",
            "amount": 5000.0,
            "currency": "RLUSD",
            "counterparty_id": "CP-SANCTIONED-007",
            "sanctions_hit": True,
            "sanctions_list": "OFAC_SDN",
            "kyc_status": "verified",
        },
        "risk_signals": {
            "volatility": "low",
            "concentration": "low",
            "liquidity_pressure": "normal",
        },
        "settlement": {
            "settlement_id": "STL-DEMO-SH-0001",
            "rail": "xrpl",
            "preconditions_met": False,
            "atomic": True,
        },
    },
    "reserve_shortfall": {
        "subject": {
            "asset_id": "ASSET-RLUSD-004",
            "issuer_id": "ISSUER-ACME-001",
            "transaction_id": "TX-DEMO-RS-0001",
        },
        "issuer": {
            "issuer_id": "ISSUER-ACME-001",
            "name": "Acme Regulated Issuer",
            "jurisdiction": "US",
            "licensed": True,
            "registry_status": "active",
        },
        "token": {
            "asset_id": "ASSET-RLUSD-004",
            "symbol": "RLUSD",
            "intended_classification": "regulated_stablecoin",
            "fiat_backed": True,
        },
        "reserves": {
            # Reserves do not cover liabilities -> hard fail.
            "reserve_ratio": 0.92,
            "liquidity_ratio": 0.20,
            "attestation_id": "ATT-RS-2026-001",
        },
        "transaction": {
            "transaction_id": "TX-DEMO-RS-0001",
            "amount": 2500.0,
            "currency": "RLUSD",
            "counterparty_id": "CP-CLEAN-004",
            "sanctions_hit": False,
            "kyc_status": "verified",
        },
        "risk_signals": {
            "volatility": "elevated",
            "concentration": "medium",
            "liquidity_pressure": "high",
        },
        "settlement": {
            "settlement_id": "STL-DEMO-RS-0001",
            "rail": "xrpl",
            "preconditions_met": False,
            "atomic": True,
        },
    },
}


def get_fixture(scenario: str) -> dict:
    """Return the demo fixture for ``scenario``.

    Raises:
        KeyError: when ``scenario`` is not one of :data:`SCENARIOS`.
    """
    if scenario not in DEMO_FIXTURES:
        raise KeyError(scenario)
    return DEMO_FIXTURES[scenario]
