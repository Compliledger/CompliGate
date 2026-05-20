from __future__ import annotations

from pydantic import BaseModel, Field

from app.models.proof import ProofArtifact


class SettlementVerifyRequest(BaseModel):
    tx_hash: str = Field(..., description="XRPL transaction hash to verify.")
    bundle: dict = Field(..., description="The permit bundle to verify against.")
    signature: str = Field(..., description="Permit bundle signature (base64).")


class SettlementVerifyByHashRequest(BaseModel):
    bundle_hash: str = Field(..., description="Hash of the original permit bundle.")
    tx_hash: str = Field(..., description="XRPL transaction hash to verify.")


class SettlementVerifyByHashResponse(BaseModel):
    decision_result: str
    reason_codes: list[str]
    proof_artifact: ProofArtifact


class TrustlineCheckRequest(BaseModel):
    address: str = Field(..., description="XRPL account address to check.")


class XRPLPaymentRequest(BaseModel):
    destination: str = Field(..., description="Destination XRPL account address.")
    amount: str | float | int = Field(..., description="Amount to send.")
    memo_bundle_hash: str | None = Field(None, description="Optional bundle hash to attach as memo.")


class ProofLink(BaseModel):
    bundle_hash: str = Field(..., description="CompliGate proof bundle hash.")
    tx_hash: str = Field(..., description="XRPL transaction hash.")


class XRPLPaymentResponse(BaseModel):
    submitted: bool = Field(..., description="Whether the transaction was submitted.")
    tx_hash: str = Field(..., description="Transaction hash on the XRPL ledger.")
    engine_result: str = Field(..., description="XRPL engine result code (e.g. tesSUCCESS).")
    validated: bool = Field(..., description="Whether the transaction was validated by the network.")
    ledger_index: int | None = Field(None, description="Ledger index in which the transaction was included.")
    network: str = Field(..., description="XRPL network identifier.")
    asset: str = Field(..., description="Asset sent (e.g. 'XRP').")
    currency: str = Field("XRP", description="Currency code of the asset sent.")
    issuer: str = Field("", description="Issuer address for IOU assets; empty string for XRP.")
    amount: str = Field(..., description="Amount sent (as string, in XRP units for native XRP payments).")
    destination: str = Field(..., description="Destination XRPL account address.")
    proof_link: ProofLink | None = Field(None, description="Linkage between CompliGate bundle hash and XRPL transaction hash.")
    testnet_amount_capped: bool = Field(False, description="True when the requested amount was capped to the testnet safety limit.")
