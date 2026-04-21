// Shared API response and domain types used across the CompliGate frontend.
//
// Centralizing these types keeps `App.tsx`, `RequestPermitPanel.tsx`, and any
// future components in sync with the backend contract and avoids duplicate
// declarations drifting apart.

export type ProofArtifact = {
  module: string;
  entity_id: string;
  rule_version_used: string;
  decision_result: string;
  evaluation_context: Record<string, unknown>;
  reason_codes: string[];
  timestamp: number;
  bundle_hash: string;
  anchor_metadata: Record<string, unknown>;
};

export type PermitPolicy = {
  version: string;
  jurisdiction: string;
};

export type PermitConstraints = {
  max_amount: number;
  allowed_counterparty?: string | null;
  reserve_backed?: boolean;
  liquidity_verified?: boolean;
  kyc_verified?: boolean;
  sanctions_check?: string;
  jurisdiction?: string;
  freeze_possible?: boolean;
  clawback_possible?: boolean;
  trustline_required?: boolean;
};

export type PermitBundle = {
  bundle_id: string;
  subject: string;
  action: string;
  exp: number;
  asset: {
    issuer: string;
    currency: string;
    classification: string;
    regulatory_treatment?: string;
    policy_id: string;
  };
  constraints: PermitConstraints;
  policy: PermitPolicy;
  attestations: Record<string, unknown>;
  scope: string[];
  nonce: string;
};

export type PermitValidity = {
  single_use: boolean;
};

export type PermitResponse = {
  summary: {
    issuer_verified: boolean;
    asset_classification: string;
    custody_attestation_bound: boolean;
    reserve_attestation_bound: boolean;
    policy_version: string;
    expires_in_seconds: number;
  };
  bundle: PermitBundle;
  signature: string;
  signed_at: number;
  expires_at: number;
  expires_in_seconds: number;
  bundle_hash: string;
  validity: PermitValidity;
  proof_artifact?: ProofArtifact;
  decision_result?: string;
  reason_codes?: string[];
};

export type VerifyResponse = {
  signature_valid: boolean;
  not_expired: boolean;
  subject?: string;
  policy_version?: string;
  action?: string;
  bundle_hash?: string;
  constraints?: PermitConstraints;
  decision_result?: string;
  reason_codes?: string[];
};

export type XRPLHealthResponse = {
  configured: boolean;
  reachable: boolean;
  network: string;
  rlusd_configured: boolean;
  demo_wallet_configured: boolean;
};

export type TrustlineCheckResponse = {
  trustline_exists: boolean;
  issuer: string | null;
  currency: string | null;
  raw_lines_checked: number;
};

export type SettlementVerifyResponse = {
  decision_result: string;
  reason_codes: string[];
  proof_artifact: Record<string, unknown>;
  tx_hash?: string;
  bundle_hash?: string;
};
