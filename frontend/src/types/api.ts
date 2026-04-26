// Shared API response and domain types used across the CompliGate frontend.
//
// Centralizing these types keeps `App.tsx`, `RequestPermitPanel.tsx`, and any
// future components in sync with the backend contract and avoids duplicate
// declarations drifting apart.

export type AnchorMetadata = Record<string, unknown>;

// ---------------------------------------------------------------------------
// Normalized compliance evidence types
// ---------------------------------------------------------------------------
//
// Earlier iterations of the API exposed compliance signals as opaque
// booleans/strings (e.g. `kyc_verified: true`, `sanctions_check: "passed"`).
// As CompliGate is wired up to real provider-backed data sources, those
// signals need to carry the actual provider, decision, reason codes, and a
// reference back to the underlying evidence so the frontend can faithfully
// render — and the backend can audit — the chain of trust.
//
// The types below model a single normalized evidence result. Each individual
// check (KYC, sanctions, reserve attestation, liquidity attestation) extends
// `BaseComplianceCheckResult` so common fields stay consistent across
// providers, while domain-specific metadata can still be expressed.

/** Normalized status of an individual compliance check. */
export type ComplianceCheckStatus =
  | "pass"
  | "fail"
  | "deny"
  | "unavailable"
  | "pending"
  | "error";

/** Normalized decision derived from a compliance check. */
export type ComplianceCheckDecision =
  | "allow"
  | "deny"
  | "review"
  | "unavailable";

/**
 * Reference to the underlying piece of evidence (document, attestation,
 * external API response, on-chain object) that backs a compliance result.
 *
 * `evidence_id` is the only required field so that even minimally-populated
 * provider responses can be linked; richer providers will populate URI,
 * cryptographic hash, retrieval timestamp, and arbitrary metadata.
 */
export type ComplianceEvidenceReference = {
  evidence_id: string;
  provider_name?: string;
  source_system?: string;
  uri?: string;
  hash?: string;
  retrieved_at?: number;
  metadata?: Record<string, unknown>;
};

/**
 * Common shape every normalized compliance check result shares.
 *
 * Specific check types extend this with domain-specific fields (e.g. matched
 * sanctions lists, reserve ratio). The `metadata` field is intentionally
 * loose so providers can pass through additional normalized attributes
 * without requiring an upfront schema change.
 */
export type BaseComplianceCheckResult = {
  provider_name?: string;
  source_system?: string;
  status: ComplianceCheckStatus;
  decision?: ComplianceCheckDecision;
  reason_codes?: string[];
  checked_at?: number;
  evidence_reference?: ComplianceEvidenceReference;
  metadata?: Record<string, unknown>;
};

export type SanctionsCheckResult = BaseComplianceCheckResult & {
  matched_lists?: string[];
  match_score?: number;
};

export type KYCCheckResult = BaseComplianceCheckResult & {
  verification_level?: string;
  identity_verified?: boolean;
};

export type ReserveCheckResult = BaseComplianceCheckResult & {
  reserve_ratio?: number;
  attestation_id?: string;
};

export type LiquidityCheckResult = BaseComplianceCheckResult & {
  available_liquidity?: number;
  currency?: string;
};

/**
 * Decision result string returned by the policy engine.
 *
 * The union spells out the explicit `unavailable` and `deny` states the
 * frontend must be able to render distinctly from `allow`. The trailing
 * `(string & {})` keeps the type forward-compatible with future decision
 * strings the backend may introduce (e.g. `"hold"`, `"escalate"`).
 */
export type DecisionResult =
  | "allow"
  | "deny"
  | "unavailable"
  | "review"
  | "pending"
  // eslint-disable-next-line @typescript-eslint/ban-types
  | (string & {});

export type ProofArtifact = {
  module: string;
  entity_id: string;
  rule_version_used: string;
  decision_result: DecisionResult;
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
 * Map of compliance evidence keyed by check name (e.g. `"kyc"`,
 * `"sanctions"`, `"reserve"`, `"liquidity"`, or any provider-specific
 * identifier). Carried alongside the legacy boolean/string constraint
 * fields so that consumers wired up to provider-backed data can render and
 * audit the actual evidence trail.
 */
export type ComplianceEvidenceMap = Record<
  string,
  | SanctionsCheckResult
  | KYCCheckResult
  | ReserveCheckResult
  | LiquidityCheckResult
  | BaseComplianceCheckResult
  | ComplianceEvidenceReference
>;

export type PermitConstraints = {
  max_amount: number;
  allowed_counterparty?: string | null;
  // The following four fields previously assumed simple boolean/string
  // values. They are now widened to also accept the normalized
  // provider-backed result types. Legacy primitives are retained so existing
  // backend payloads continue to deserialize without modification, while
  // newer payloads can carry the full evidence object.
  reserve_backed?: boolean | ReserveCheckResult;
  liquidity_verified?: boolean | LiquidityCheckResult;
  kyc_verified?: boolean | KYCCheckResult;
  sanctions_check?: string | SanctionsCheckResult;
  // Optional dedicated fields for callers that prefer not to overload the
  // legacy field names. When present, these should be considered
  // authoritative over the legacy primitives.
  reserve_check?: ReserveCheckResult;
  liquidity_check?: LiquidityCheckResult;
  kyc_check?: KYCCheckResult;
  sanctions_check_result?: SanctionsCheckResult;
  jurisdiction?: string;
  freeze_possible?: boolean;
  clawback_possible?: boolean;
  trustline_required?: boolean;
  /** Map of normalized provider-backed evidence keyed by check name. */
  evidence?: ComplianceEvidenceMap;
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
  decision_result?: DecisionResult;
  reason_codes?: string[];
  /**
   * Provider-backed evidence references surfaced alongside the proof
   * artifact's `evaluation_context`. Populated when the policy engine has
   * pulled normalized data from upstream compliance providers.
   */
  evidence_references?: ComplianceEvidenceMap;
  /**
   * Explicit unavailable state — set by the backend when one or more
   * required compliance providers could not be reached and the permit was
   * therefore not issued / not fully evaluated.
   */
  unavailable?: boolean;
  /**
   * Explicit deny state — set when a provider returned a hard deny for
   * the requested action (separate from `unavailable`).
   */
  denied?: boolean;
};

export type VerifyResponse = {
  signature_valid: boolean;
  not_expired: boolean;
  subject?: string;
  policy_version?: string;
  action?: string;
  bundle_hash?: string;
  constraints?: PermitConstraints;
  decision_result?: DecisionResult;
  reason_codes?: string[];
  /** Provider-backed evidence references re-checked at verification time. */
  evidence_references?: ComplianceEvidenceMap;
  /** Explicit unavailable state when a compliance provider could not be reached. */
  unavailable?: boolean;
  /** Explicit deny state for verifications that are blocked outright. */
  denied?: boolean;
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
  decision_result: DecisionResult;
  reason_codes: string[];
  proof_artifact: ProofArtifact;
  tx_hash?: string;
  bundle_hash?: string;
  /**
   * Provider-backed evidence references gathered while verifying the
   * settlement (e.g. post-trade reserve / liquidity attestations).
   */
  evidence_references?: ComplianceEvidenceMap;
  /** Explicit unavailable state when verification could not complete. */
  unavailable?: boolean;
  /** Explicit deny state when the settlement is rejected. */
  denied?: boolean;
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
