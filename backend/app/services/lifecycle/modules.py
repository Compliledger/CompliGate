"""Stub implementations of the thin-MVP CompliStack modules.

Each class mirrors the named service from the lifecycle spec and exposes
a single classmethod that returns a
:class:`app.models.compliproof.ModuleDecision`. The stubs are
intentionally deterministic and driven entirely by the demo fixture
inputs so the ``/lifecycle/run-demo`` endpoint behaves predictably.

These stubs are *not* meant to replace the real provider-backed
services exposed elsewhere in the application; they exist solely to
power the universal lifecycle demo.
"""

from __future__ import annotations

from datetime import datetime

from app.models.compliproof import ModuleDecision, ModuleDecisionResult


# Thresholds used by the stub solvency / risk modules. Kept here as
# constants so they are easy to tweak for demos.
_MIN_RESERVE_RATIO = 1.0
_MIN_LIQUIDITY_RATIO = 0.10


class MarketProof:
    """Stub MarketProof issuer-validation module."""

    RULE_VERSION = "marketproof-1.0"

    @classmethod
    def validate_issuer(cls, issuer: dict) -> ModuleDecision:
        licensed = bool(issuer.get("licensed"))
        active = issuer.get("registry_status") == "active"
        if licensed and active:
            return ModuleDecision(
                module="MarketProof",
                decision=ModuleDecisionResult.PASS,
                reason_codes=["ISSUER_LICENSED", "ISSUER_REGISTRY_ACTIVE"],
                rule_version=cls.RULE_VERSION,
                evidence_reference=issuer.get("issuer_id"),
            )
        reason_codes: list[str] = []
        if not licensed:
            reason_codes.append("ISSUER_NOT_LICENSED")
        if not active:
            reason_codes.append("ISSUER_REGISTRY_INACTIVE")
        return ModuleDecision(
            module="MarketProof",
            decision=ModuleDecisionResult.FAIL,
            reason_codes=reason_codes,
            rule_version=cls.RULE_VERSION,
            evidence_reference=issuer.get("issuer_id"),
        )


class TokenProof:
    """Stub TokenProof token-classification module."""

    RULE_VERSION = "tokenproof-1.0"

    @classmethod
    def classify_token(cls, token: dict) -> ModuleDecision:
        classification = token.get("intended_classification") or "unclassified"
        if classification == "regulated_stablecoin" and token.get("fiat_backed"):
            return ModuleDecision(
                module="TokenProof",
                decision=ModuleDecisionResult.PASS,
                reason_codes=["TOKEN_CLASSIFIED_REGULATED_STABLECOIN"],
                rule_version=cls.RULE_VERSION,
                evidence_reference=token.get("asset_id"),
            )
        return ModuleDecision(
            module="TokenProof",
            decision=ModuleDecisionResult.CONDITIONAL,
            reason_codes=["TOKEN_CLASSIFICATION_REVIEW"],
            rule_version=cls.RULE_VERSION,
            evidence_reference=token.get("asset_id"),
        )


class SolvencyProof:
    """Stub SolvencyProof reserve & liquidity check module."""

    RULE_VERSION = "solvencyproof-1.0"

    @classmethod
    def check_reserves_and_liquidity(cls, reserves: dict) -> ModuleDecision:
        reserve_ratio = float(reserves.get("reserve_ratio", 0.0))
        liquidity_ratio = float(reserves.get("liquidity_ratio", 0.0))
        attestation_id = reserves.get("attestation_id")

        if reserve_ratio < _MIN_RESERVE_RATIO:
            return ModuleDecision(
                module="SolvencyProof",
                decision=ModuleDecisionResult.FAIL,
                reason_codes=["RESERVE_SHORTFALL"],
                rule_version=cls.RULE_VERSION,
                evidence_reference=attestation_id,
            )
        if liquidity_ratio < _MIN_LIQUIDITY_RATIO:
            return ModuleDecision(
                module="SolvencyProof",
                decision=ModuleDecisionResult.CONDITIONAL,
                reason_codes=["LIQUIDITY_BUFFER_LOW"],
                rule_version=cls.RULE_VERSION,
                evidence_reference=attestation_id,
            )
        return ModuleDecision(
            module="SolvencyProof",
            decision=ModuleDecisionResult.PASS,
            reason_codes=["RESERVES_OK", "LIQUIDITY_OK"],
            rule_version=cls.RULE_VERSION,
            evidence_reference=attestation_id,
        )


class CompliGate:
    """Stub CompliGate transaction-authorization module.

    Note: the application also exposes a richer ``CompliGate``
    permit-issuance flow elsewhere; this stub captures only the
    transaction-level authorization decision needed by the lifecycle
    demo.
    """

    RULE_VERSION = "compligate-auth-1.0"

    @classmethod
    def authorize_transaction(cls, transaction: dict) -> ModuleDecision:
        if transaction.get("sanctions_hit"):
            return ModuleDecision(
                module="CompliGate",
                decision=ModuleDecisionResult.FAIL,
                reason_codes=["SANCTIONS_HIT"],
                rule_version=cls.RULE_VERSION,
                evidence_reference=transaction.get("transaction_id"),
            )
        if transaction.get("kyc_status") != "verified":
            return ModuleDecision(
                module="CompliGate",
                decision=ModuleDecisionResult.FAIL,
                reason_codes=["KYC_NOT_VERIFIED"],
                rule_version=cls.RULE_VERSION,
                evidence_reference=transaction.get("transaction_id"),
            )
        return ModuleDecision(
            module="CompliGate",
            decision=ModuleDecisionResult.PASS,
            reason_codes=["TRANSACTION_AUTHORIZED"],
            rule_version=cls.RULE_VERSION,
            evidence_reference=transaction.get("transaction_id"),
        )


class CompliGuard:
    """Stub CompliGuard real-time risk-monitoring module."""

    RULE_VERSION = "compliguard-1.0"

    @classmethod
    def monitor_risk(cls, risk_signals: dict) -> ModuleDecision:
        liquidity_pressure = risk_signals.get("liquidity_pressure", "normal")
        volatility = risk_signals.get("volatility", "low")
        concentration = risk_signals.get("concentration", "low")

        if liquidity_pressure == "high" or volatility == "high":
            return ModuleDecision(
                module="CompliGuard",
                decision=ModuleDecisionResult.FAIL,
                reason_codes=["RISK_THRESHOLD_BREACHED"],
                rule_version=cls.RULE_VERSION,
            )
        if (
            liquidity_pressure == "elevated"
            or volatility == "elevated"
            or concentration == "medium"
        ):
            return ModuleDecision(
                module="CompliGuard",
                decision=ModuleDecisionResult.CONDITIONAL,
                reason_codes=["RISK_ELEVATED"],
                rule_version=cls.RULE_VERSION,
            )
        return ModuleDecision(
            module="CompliGuard",
            decision=ModuleDecisionResult.PASS,
            reason_codes=["RISK_WITHIN_LIMITS"],
            rule_version=cls.RULE_VERSION,
        )


class SettlementGuard:
    """Stub SettlementGuard pre-settlement validation module."""

    RULE_VERSION = "settlementguard-1.0"

    @classmethod
    def validate_settlement(cls, settlement: dict, *, gate_passed: bool) -> ModuleDecision:
        # Settlement cannot proceed if the upstream authorization step
        # already failed, even if the static settlement fixture looks ok.
        if not gate_passed:
            return ModuleDecision(
                module="SettlementGuard",
                decision=ModuleDecisionResult.FAIL,
                reason_codes=["SETTLEMENT_BLOCKED_UPSTREAM_FAIL"],
                rule_version=cls.RULE_VERSION,
                evidence_reference=settlement.get("settlement_id"),
            )
        if not settlement.get("preconditions_met", False):
            return ModuleDecision(
                module="SettlementGuard",
                decision=ModuleDecisionResult.FAIL,
                reason_codes=["SETTLEMENT_PRECONDITIONS_NOT_MET"],
                rule_version=cls.RULE_VERSION,
                evidence_reference=settlement.get("settlement_id"),
            )
        if not settlement.get("atomic", False):
            return ModuleDecision(
                module="SettlementGuard",
                decision=ModuleDecisionResult.CONDITIONAL,
                reason_codes=["SETTLEMENT_NON_ATOMIC"],
                rule_version=cls.RULE_VERSION,
                evidence_reference=settlement.get("settlement_id"),
            )
        return ModuleDecision(
            module="SettlementGuard",
            decision=ModuleDecisionResult.PASS,
            reason_codes=["SETTLEMENT_VALIDATED"],
            rule_version=cls.RULE_VERSION,
            evidence_reference=settlement.get("settlement_id"),
        )


class AlgorandAdapter:
    """Stub Algorand anchor adapter for the demo lifecycle.

    The real adapter would submit a transaction to the Algorand network
    that anchors the canonical proof hash. For the demo we synthesize a
    deterministic, network-shaped tx id from the proof hash so the
    response is reproducible and the explorer URL is well-formed.
    """

    NETWORK = "algorand_testnet"
    EXPLORER_URL_TEMPLATE = "https://lora.algokit.io/testnet/transaction/{tx_id}"

    @classmethod
    def anchor_proof(cls, proof_hash_hex: str, anchored_at: datetime) -> dict:
        # Algorand transaction ids are 52-character base32 strings. We
        # emit a synthetic but obviously-demo value derived from the
        # proof hash so it is stable across runs of the same scenario
        # without pretending to be a real on-chain anchor.
        if not proof_hash_hex:
            raise ValueError("proof_hash_hex must be a non-empty string")
        tx_id = f"DEMO{proof_hash_hex.upper()[:48]}"
        return {
            "chain": "algorand",
            "network": cls.NETWORK,
            "tx_id": tx_id,
            "explorer_url": cls.EXPLORER_URL_TEMPLATE.format(tx_id=tx_id),
            "anchored_at": anchored_at,
        }
