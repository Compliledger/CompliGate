// Shared API response and domain types used across the CompliGate frontend.
//
// Centralizing these types keeps `App.tsx`, `RequestPermitPanel.tsx`, and any
// future components in sync with the backend contract and avoids duplicate
// declarations drifting apart.

export type AnchorMetadata = Record<string, unknown>;

/**
 * Typed shape for the `evaluation_context` carried inside a proof
 * artifact. The backend records the *real* evidence references
 * returned by the configured compliance providers — sanctions, KYC
 * (subject and, where applicable, destination), and reserve /
 * liquidity. Each field is `null` (or absent) when no provider
 * returned a reference; the artifact never fabricates one.
 *
 * The type is intentionally permissive (`& Record<string, unknown>`):
 * `evaluation_context` is the open extension point of the proof
 * artifact and may carry additional, module-specific keys (for
 * example `tx_hash`, `permit_bundle`, `compliance_evidence`) that
 * downstream auditors may inspect but the renderer does not need to
 * know about.
 */
export type ProofArtifactEvaluationContext = {
  sanctions_reference?: string | null;
  kyc_reference?: string | null;
  kyc_destination_reference?: string | null;
  reserve_reference?: string | null;
  liquidity_reference?: string | null;
} & Record<string, unknown>;

/**
 * Universal proof artifact shape emitted by the backend for every
 * compliance decision (permit issuance, settlement verification,
 * etc.). A proof artifact is *authorization / verification evidence*
 * only — it records that a decision was evaluated and what evidence
 * backed it. It does **not** imply that any on-ledger enforcement
 * action was taken.
 */
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
  evaluation_context: ProofArtifactEvaluationContext;
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
  /**
   * Reserve / KYC booleans are derived from the engine-normalized
   * provider statuses. They are `true` only when the provider returned
   * an explicitly approved / verified state; `false` otherwise (denied
   * or unavailable). To distinguish denied from unavailable, render
   * `summary.kyc_status` / `summary.reserve_status` etc. instead.
   */
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
