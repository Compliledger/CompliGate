// Shared API response and domain types used across the CompliGate frontend.
//
// Centralizing these types keeps `App.tsx`, `RequestPermitPanel.tsx`, and any
// future components in sync with the backend contract and avoids duplicate
// declarations drifting apart.

export type AnchorMetadata = Record<string, unknown>;

export type ProofArtifact = {
  module: string;
  entity_id: string;
  rule_version_used: string;
  decision_result: string;
  evaluation_context: Record<string, unknown>;
  reason_codes: string[];
  timestamp: number;
  bundle_hash: string;
  anchor_metadata: AnchorMetadata;
};

export type PermitPolicy = {
  version: string;
  jurisdiction: string;
};

/**
 * Status vocabulary used by the cross-cutting compliance providers
 * (KYC, sanctions, reserve). Mirrors `ProviderStatus` in the backend.
 *
 * `"missing"` is reported in the permit summary when no provider was
 * wired up at all (the engine emits a fail-closed denial alongside it).
 */
export type ProviderStatusValue =
  | "approved"
  | "denied"
  | "unavailable"
  | "missing";

/**
 * Status vocabulary of the normalized KYC result returned by KYC
 * providers / upstream assertions. Distinct from the cross-cutting
 * `ProviderStatusValue` because KYC sources speak a domain-specific
 * vocabulary.
 */
export type KycStatusValue = "verified" | "not_verified" | "unavailable";

/**
 * Status vocabulary of the normalized reserve / liquidity result
 * returned by reserve providers / custodian attestations.
 */
export type ReserveStatusValue = "verified" | "not_verified" | "unavailable";

/**
 * Sanctions check projection in the permit bundle constraints. The
 * backend records the literal string returned by the sanctions
 * provider so the bundle does not fabricate a passed/failed boolean.
 */
export type SanctionsConstraintValue = "passed" | "denied" | "unavailable";

/**
 * Normalized KYC result surfaced as a first-class attestation in the
 * permit bundle. Mirrors `KycResult.to_dict()` in the backend.
 */
export type KycResult = {
  provider_name: string;
  /** Alias of `provider_name`; kept for compatibility with the backend payload. */
  source_system: string;
  subject_id: string;
  kyc_status: KycStatusValue;
  jurisdiction: string;
  checked_at: number;
  evidence_reference: string | null;
  reason_codes: string[];
};

/**
 * Normalized reserve / liquidity result surfaced as a first-class
 * attestation in the permit bundle. Mirrors `ReserveResult.to_dict()`
 * in the backend.
 */
export type ReserveResult = {
  provider_name: string;
  /** Alias of `provider_name`; kept for compatibility with the backend payload. */
  attestor_name: string;
  reserve_status: ReserveStatusValue;
  liquidity_status: ReserveStatusValue;
  evidence_reference: string | null;
  checked_at: number;
  reason_codes: string[];
};

/**
 * Per-check evidence record produced by a compliance provider. Mirrors
 * `ProviderResult.to_evidence()` in the backend.
 */
export type ComplianceEvidenceItem = {
  check: string;
  status: ProviderStatusValue;
  provider_id: string;
  reference: string | null;
  reason: string | null;
  checked_at: number;
  details: Record<string, unknown>;
};

/**
 * Real provider-backed attestation references (and normalized result
 * payloads) carried inside the permit bundle. Each field is `null`
 * when the corresponding provider did not return evidence — the bundle
 * never fabricates an attestation that does not exist.
 */
export type PermitAttestations = {
  kyc_reference: string | null;
  kyc_result: KycResult | null;
  kyc_destination_reference: string | null;
  kyc_destination_result: KycResult | null;
  reserve_reference: string | null;
  liquidity_reference: string | null;
  reserve_result: ReserveResult | null;
  sanctions_reference: string | null;
};

export type PermitConstraints = {
  max_amount: number;
  /** Original requested amount, when supplied. */
  amount?: number | null;
  /** Whether the requested amount is within `max_amount`. */
  within_limit?: boolean;
  allowed_counterparty?: string | null;
  /**
   * Reserve / KYC booleans are derived from the engine-normalized
   * provider statuses. They are `true` only when the provider returned
   * an explicitly approved / verified state; `false` otherwise (denied
   * or unavailable). To distinguish denied from unavailable, render
   * `summary.kyc_status` / `summary.reserve_status` etc. instead.
   */
  reserve_backed?: boolean;
  liquidity_verified?: boolean;
  kyc_verified?: boolean;
  sanctions_check?: SanctionsConstraintValue;
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
  attestations: PermitAttestations;
  /** Raw evidence records from each configured compliance provider. */
  compliance_evidence?: ComplianceEvidenceItem[];
  scope: string[];
  nonce: string;
};

export type PermitValidity = {
  single_use: boolean;
};

/**
 * Permit summary surfaced alongside the signed bundle. Reflects the
 * real provider-backed state: `issuer_verified` is a configuration
 * assertion (issuer address has been configured), and the four
 * `*_status` fields carry the normalized provider outcomes used to
 * justify the decision.
 */
export type PermitSummary = {
  issuer_verified: boolean;
  asset_classification: string;
  kyc_status: ProviderStatusValue;
  sanctions_status: ProviderStatusValue;
  reserve_status: ProviderStatusValue;
  liquidity_status: ProviderStatusValue;
  policy_version: string;
  expires_in_seconds: number;
};

export type PermitResponse = {
  summary: PermitSummary;
  bundle: PermitBundle;
  signature: string;
  signed_at: number;
  expires_at: number;
  expires_in_seconds: number;
  bundle_hash: string;
  validity: PermitValidity;
  proof_artifact: ProofArtifact;
  decision_result: string;
  reason_codes: string[];
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
  signing_enabled?: boolean;
  signing_mode?: string;
  signer_configured?: boolean;
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
  proof_artifact: ProofArtifact;
  tx_hash?: string;
  bundle_hash?: string;
};

export type ProofLink = {
  bundle_hash: string;
  tx_hash: string;
};

export type XRPLPaymentResponse = {
  submitted: boolean;
  tx_hash: string;
  engine_result: string;
  network: string;
  currency: string;
  issuer: string;
  amount: string;
  destination: string;
  proof_link?: ProofLink | null;
};
