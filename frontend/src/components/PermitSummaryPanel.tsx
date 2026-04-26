import { useMemo, type ReactNode } from "react";

import StatusMessage from "./StatusMessage";
import {
  classifySettlement,
  formatSeconds,
  isDeniedDecision,
  outcomeClass,
  outcomeLabel,
  outcomeSymbol,
  outcomeTextClass,
  providerOutcome,
  unavailableReasonCodes,
  type ProviderOutcome,
  type SettlementOutcome,
} from "../lib/format";
import type {
  ComplianceEvidenceItem,
  KycResult,
  PermitResponse,
  ReserveResult,
  SettlementVerifyResponse,
} from "../types/api";

export type PermitStatus = {
  label: string;
  kind: "neutral" | "good" | "warn" | "bad" | "anchored";
};

type Props = {
  permit: PermitResponse | null;
  /** Page-level header status (drives the badge in the panel header). */
  status: PermitStatus;
  /** Seconds remaining before the permit expires (0 when no permit / expired). */
  remaining: number;
  /**
   * Optional settlement verification result. When provided the panel renders
   * the actual settlement outcome in the "Settlement Verification" section
   * rather than a placeholder.
   */
  settlementResult?: SettlementVerifyResponse | null;
  /** Optional CSS flex order, used to position among sibling panels. */
  order?: number;
};

// ---------------------------------------------------------------------------
// Section primitive
// ---------------------------------------------------------------------------

/**
 * Visual variant of a section header. Mirrors the four-state
 * `ProviderOutcome` plus a neutral state used for sections that do not
 * map onto a provider outcome (e.g. asset classification, XRPL
 * preconditions when no signal is present yet).
 */
type SectionState = ProviderOutcome | "neutral";

function sectionStateFromOutcome(o: ProviderOutcome): SectionState {
  return o;
}

function sectionStateClass(state: SectionState): string {
  switch (state) {
    case "verified":
      return "controlSectionVerified";
    case "denied":
      return "controlSectionDenied";
    case "unavailable":
      return "controlSectionUnavailable";
    case "not_evaluated":
      return "controlSectionNotEvaluated";
    case "neutral":
      return "controlSectionNeutral";
  }
}

function sectionStateLabel(state: SectionState): string {
  switch (state) {
    case "verified":
      return "Verified";
    case "denied":
      return "Denied";
    case "unavailable":
      return "Unavailable";
    case "not_evaluated":
      return "Not Evaluated";
    case "neutral":
      return "Configured";
  }
}

type ControlSectionProps = {
  title: string;
  state: SectionState;
  /** Human-readable outcome label override (e.g. "PASS" for settlement). */
  outcomeLabelOverride?: string;
  /** Provider / source name; rendered in the meta line when present. */
  provider?: string | null;
  /** Evidence reference identifier; rendered in the meta line when present. */
  evidence?: string | null;
  /** Reason codes displayed below the meta line. Empty array = no codes. */
  reasonCodes?: readonly string[];
  /**
   * Highlighted (warn-styled) reason codes — typically the
   * `*_UNAVAILABLE` subset.
   */
  unavailableCodes?: readonly string[];
  /** Optional inline rows for additional structured fields. */
  children?: ReactNode;
  /** Optional test id for assertions. */
  testId?: string;
};

function ControlSection({
  title,
  state,
  outcomeLabelOverride,
  provider,
  evidence,
  reasonCodes,
  unavailableCodes,
  children,
  testId,
}: ControlSectionProps) {
  const stateClass = sectionStateClass(state);
  const label = outcomeLabelOverride ?? sectionStateLabel(state);
  const codes = reasonCodes ?? [];
  const unavailable = unavailableCodes ?? [];
  return (
    <div
      className={`controlSection ${stateClass}`}
      data-testid={testId}
      data-state={state}
    >
      <div className="controlSectionHeader">
        <span className="controlSectionTitle">{title}</span>
        <span className={`controlSectionBadge ${stateClass}`}>{label}</span>
      </div>
      {(provider || evidence) && (
        <div className="controlSectionMeta">
          {provider && (
            <span className="controlSectionMetaItem">
              <span className="controlSectionMetaLabel">Source</span>
              {provider}
            </span>
          )}
          {evidence && (
            <span className="controlSectionMetaItem">
              <span className="controlSectionMetaLabel">Evidence</span>
              <span className="controlSectionEvidence">{evidence}</span>
            </span>
          )}
        </div>
      )}
      {children && <div className="controlSectionRows">{children}</div>}
      {codes.length > 0 && (
        <div className="controlSectionCodes">
          {codes.map((rc) => (
            <span
              key={rc}
              className={`reasonCode ${
                unavailable.includes(rc)
                  ? "reasonCodeWarn"
                  : state === "denied"
                  ? "reasonCodeBad"
                  : ""
              }`}
            >
              {rc}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function ControlRow({
  label,
  value,
  outcome,
}: {
  label: string;
  value: ReactNode;
  outcome?: ProviderOutcome;
}) {
  return (
    <div className="controlSectionRow">
      {outcome && (
        <span className={outcomeClass(outcome)}>{outcomeSymbol(outcome)}</span>
      )}
      <span className="controlSectionRowLabel">{label}</span>
      <span
        className={`controlSectionRowValue${
          outcome ? ` ${outcomeTextClass(outcome)}` : ""
        }`}
      >
        {value}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function findEvidence(
  items: ComplianceEvidenceItem[] | undefined,
  check: string,
): ComplianceEvidenceItem | undefined {
  return items?.find((e) => e.check === check);
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value : null;
}

/**
 * Filter top-level reason codes to those relevant to a particular check
 * family. Used so each section displays only the codes that actually
 * apply to it (e.g. SANCTIONS_* under sanctions, KYC_* under KYC).
 */
function filterReasonCodes(
  codes: readonly string[] | null | undefined,
  pattern: RegExp,
): string[] {
  if (!codes) return [];
  return codes.filter((rc) => pattern.test(rc));
}

function settlementSectionState(outcome: SettlementOutcome): SectionState {
  switch (outcome) {
    case "pass":
      return "verified";
    case "fail":
      return "denied";
    case "unavailable":
      return "unavailable";
  }
}

function settlementOutcomeLabel(outcome: SettlementOutcome): string {
  switch (outcome) {
    case "pass":
      return "PASS";
    case "fail":
      return "FAIL";
    case "unavailable":
      return "UNAVAILABLE";
  }
}

// ---------------------------------------------------------------------------
// PermitSummaryPanel
// ---------------------------------------------------------------------------

/**
 * PermitSummaryPanel
 *
 * Renders the permit constraints snapshot organized around the **real
 * regulatory control results** returned by the backend. Each section
 * surfaces the outcome, the provider / source that produced it, the
 * underlying evidence reference (when emitted) and any relevant reason
 * codes — without fabricating synthetic booleans.
 *
 * Sections:
 *   1. Asset Classification
 *   2. Sanctions / AML
 *   3. KYC / Identity
 *   4. Reserve / Liquidity
 *   5. XRPL Preconditions
 *   6. Settlement Verification
 *
 * Pure presentation: receives the permit, derived header status, and
 * (optionally) the settlement verification result from its parent so
 * the page-level orchestrator keeps the canonical state.
 */
export default function PermitSummaryPanel({
  permit,
  status,
  remaining,
  settlementResult,
  order,
}: Props) {
  const expiryPercent = useMemo(() => {
    if (!permit || remaining <= 0 || permit.expires_in_seconds <= 0) return 0;
    return Math.min(100, (remaining / permit.expires_in_seconds) * 100);
  }, [permit, remaining]);

  return (
    <section
      className="card"
      style={order !== undefined ? { order } : undefined}
      data-testid="permit-summary-panel"
    >
      <div className="summaryHeader">
        <h2>Permit Constraints Snapshot</h2>
        <span className={`badge ${status.kind}`}>
          <span className="badgeDot" />
          {status.label}
        </span>
      </div>

      {!permit ? (
        <StatusMessage variant="empty" title="No permit yet">
          Request a permit to view the control results.
        </StatusMessage>
      ) : (
        <>
          {(() => {
            const decision =
              permit.decision_result ?? permit.proof_artifact?.decision_result;
            const reasonCodes =
              permit.reason_codes ?? permit.proof_artifact?.reason_codes ?? [];
            const denied =
              permit.denied || permit.unavailable || isDeniedDecision(decision);
            if (!denied) return null;
            const unavailable = unavailableReasonCodes(reasonCodes);
            const variant = unavailable.length > 0 ? "warning" : "error";
            const title =
              unavailable.length > 0
                ? "Permit denied — required compliance check unavailable"
                : "Permit denied";
            return (
              <StatusMessage variant={variant} title={title}>
                <div data-testid="permit-summary-denial">
                  <p style={{ margin: "0 0 8px" }}>
                    {unavailable.length > 0
                      ? "The backend failed closed because one or more required provider checks could not return a definitive result. The control results below reflect the unverified state and must not be treated as a passing compliance outcome."
                      : "The backend denied this permit. The control results below reflect the unverified state and must not be treated as a passing compliance outcome."}
                  </p>
                  {reasonCodes.length > 0 && (
                    <div
                      className="reasonCodesList"
                      data-testid="permit-summary-denial-codes"
                    >
                      {reasonCodes.map((rc) => (
                        <span
                          key={rc}
                          className={`reasonCode ${
                            unavailable.includes(rc)
                              ? "reasonCodeWarn"
                              : "reasonCodeBad"
                          }`}
                        >
                          {rc}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </StatusMessage>
            );
          })()}

          <PermitMetaRow permit={permit} remaining={remaining} />

          <div className="controlSections">
            <AssetClassificationSection permit={permit} />
            <SanctionsSection permit={permit} />
            <KycSection permit={permit} />
            <ReserveLiquiditySection permit={permit} />
            <XrplPreconditionsSection permit={permit} />
            <SettlementSection settlementResult={settlementResult ?? null} />
          </div>

          <div className="expiryBarWrap">
            <div
              className={`expiryBarFill${
                remaining <= 0
                  ? " expiryExpired"
                  : remaining < 60
                  ? " expiryWarn"
                  : ""
              }`}
              style={{ width: `${expiryPercent}%` }}
            />
          </div>
        </>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Compact meta row (policy version + expiry)
// ---------------------------------------------------------------------------

function PermitMetaRow({
  permit,
  remaining,
}: {
  permit: PermitResponse;
  remaining: number;
}) {
  return (
    <div className="permitMetaRow">
      <span className="permitMetaItem">
        <span className="controlSectionMetaLabel">Policy</span>
        {permit.summary.policy_version}
      </span>
      <span
        className={`permitMetaItem${
          remaining <= 0
            ? " textBad"
            : remaining < 60
            ? " textWarn"
            : ""
        }`}
      >
        <span className="controlSectionMetaLabel">Expires in</span>
        {remaining > 0 ? formatSeconds(remaining) : "Expired"}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Section: Asset Classification
// ---------------------------------------------------------------------------

function AssetClassificationSection({ permit }: { permit: PermitResponse }) {
  const { issuer_verified, asset_classification } = permit.summary;
  const { classification, regulatory_treatment, policy_id, currency, issuer } =
    permit.bundle.asset;
  // Asset classification is configuration, not a provider check. We use
  // the four-state outcome only so the badge styling stays consistent
  // with the other sections: verified when an issuer is configured and
  // a classification has been assigned, not_evaluated otherwise.
  const state: SectionState =
    issuer_verified && asset_classification
      ? "verified"
      : issuer_verified
      ? "neutral"
      : "not_evaluated";
  const outcomeLabelOverride = state === "verified" ? "Classified" : undefined;
  return (
    <ControlSection
      title="Asset Classification"
      state={state}
      outcomeLabelOverride={outcomeLabelOverride}
      provider="Issuer configuration"
      evidence={nonEmptyString(policy_id)}
      testId="control-section-asset-classification"
    >
      <ControlRow
        label="Classification"
        value={asset_classification || classification || "—"}
      />
      {regulatory_treatment && (
        <ControlRow label="Regulatory treatment" value={regulatory_treatment} />
      )}
      {currency && <ControlRow label="Currency" value={currency} />}
      {issuer && (
        <ControlRow
          label="Issuer"
          value={<span className="breakAll">{issuer}</span>}
        />
      )}
    </ControlSection>
  );
}

// ---------------------------------------------------------------------------
// Section: Sanctions / AML
// ---------------------------------------------------------------------------

function SanctionsSection({ permit }: { permit: PermitResponse }) {
  const status = permit.summary.sanctions_status;
  const outcome = providerOutcome(status);
  const evidenceItem = findEvidence(permit.bundle.compliance_evidence, "sanctions");
  const provider = evidenceItem?.provider_id ?? null;
  const reference =
    nonEmptyString(permit.bundle.attestations.sanctions_reference) ??
    nonEmptyString(evidenceItem?.reference);
  const topLevelCodes =
    permit.reason_codes ?? permit.proof_artifact?.reason_codes ?? [];
  const filtered = filterReasonCodes(topLevelCodes, /SANCTIONS|AML/i);
  const itemReason = nonEmptyString(evidenceItem?.reason ?? null);
  const codes = itemReason && !filtered.includes(itemReason)
    ? [...filtered, itemReason]
    : filtered;
  const unavailable = unavailableReasonCodes(codes);
  return (
    <ControlSection
      title="Sanctions / AML"
      state={sectionStateFromOutcome(outcome)}
      provider={provider}
      evidence={reference}
      reasonCodes={codes}
      unavailableCodes={unavailable}
      testId="control-section-sanctions"
    />
  );
}

// ---------------------------------------------------------------------------
// Section: KYC / Identity
// ---------------------------------------------------------------------------

function kycLine(label: string, result: KycResult | null, reference: string | null) {
  if (!result && !reference) return null;
  const outcome = result
    ? providerOutcome(result.kyc_status)
    : reference
    ? "verified"
    : "not_evaluated";
  return (
    <ControlRow
      label={label}
      outcome={outcome}
      value={
        <span className="controlSectionRowValueInner">
          <span>{outcomeLabel(outcome)}</span>
          {result?.jurisdiction && (
            <span className="controlSectionRowAside">
              {result.jurisdiction}
            </span>
          )}
        </span>
      }
    />
  );
}

function KycSection({ permit }: { permit: PermitResponse }) {
  const subjectStatus = permit.summary.kyc_status;
  const outcome = providerOutcome(subjectStatus);
  const subject = permit.bundle.attestations.kyc_result;
  const destination = permit.bundle.attestations.kyc_destination_result;
  const subjectRef = nonEmptyString(permit.bundle.attestations.kyc_reference);
  const destinationRef = nonEmptyString(
    permit.bundle.attestations.kyc_destination_reference,
  );
  const evidenceItem = findEvidence(permit.bundle.compliance_evidence, "kyc");
  const provider =
    subject?.provider_name ?? evidenceItem?.provider_id ?? null;
  const topLevelCodes =
    permit.reason_codes ?? permit.proof_artifact?.reason_codes ?? [];
  const filtered = filterReasonCodes(topLevelCodes, /KYC|IDENTITY/i);
  const merged = new Set<string>(filtered);
  for (const rc of subject?.reason_codes ?? []) merged.add(rc);
  for (const rc of destination?.reason_codes ?? []) merged.add(rc);
  const codes = Array.from(merged);
  const unavailable = unavailableReasonCodes(codes);
  return (
    <ControlSection
      title="KYC / Identity"
      state={sectionStateFromOutcome(outcome)}
      provider={provider}
      evidence={subjectRef}
      reasonCodes={codes}
      unavailableCodes={unavailable}
      testId="control-section-kyc"
    >
      {kycLine("Subject", subject, subjectRef)}
      {kycLine("Destination", destination, destinationRef)}
    </ControlSection>
  );
}

// ---------------------------------------------------------------------------
// Section: Reserve / Liquidity
// ---------------------------------------------------------------------------

function ReserveLiquiditySection({ permit }: { permit: PermitResponse }) {
  const reserveStatus = permit.summary.reserve_status;
  const liquidityStatus = permit.summary.liquidity_status;
  const reserveOutcome = providerOutcome(reserveStatus);
  const liquidityOutcome = providerOutcome(liquidityStatus);
  // The section header reflects the *worse* of the two outcomes so the
  // operator immediately sees the riskier signal — a denied reserve is
  // not masked by a verified liquidity attestation, and vice versa.
  const overall = combineOutcomes(reserveOutcome, liquidityOutcome);
  const result: ReserveResult | null = permit.bundle.attestations.reserve_result;
  const provider = result?.provider_name ?? result?.attestor_name ?? null;
  const reserveRef = nonEmptyString(permit.bundle.attestations.reserve_reference);
  const liquidityRef = nonEmptyString(
    permit.bundle.attestations.liquidity_reference,
  );
  const evidenceRef = reserveRef ?? liquidityRef;
  const topLevelCodes =
    permit.reason_codes ?? permit.proof_artifact?.reason_codes ?? [];
  const filtered = filterReasonCodes(topLevelCodes, /RESERVE|LIQUIDITY/i);
  const merged = new Set<string>(filtered);
  for (const rc of result?.reason_codes ?? []) merged.add(rc);
  const codes = Array.from(merged);
  const unavailable = unavailableReasonCodes(codes);
  return (
    <ControlSection
      title="Reserve / Liquidity"
      state={sectionStateFromOutcome(overall)}
      provider={provider}
      evidence={evidenceRef}
      reasonCodes={codes}
      unavailableCodes={unavailable}
      testId="control-section-reserve-liquidity"
    >
      <ControlRow
        label="Reserve backing"
        outcome={reserveOutcome}
        value={outcomeLabel(reserveOutcome)}
      />
      <ControlRow
        label="Liquidity"
        outcome={liquidityOutcome}
        value={outcomeLabel(liquidityOutcome)}
      />
      {reserveRef && liquidityRef && reserveRef !== liquidityRef && (
        <ControlRow
          label="Liquidity evidence"
          value={<span className="breakAll">{liquidityRef}</span>}
        />
      )}
    </ControlSection>
  );
}

/**
 * Combine two provider outcomes into a single "worst-of" outcome. The
 * ordering is denied > unavailable > not_evaluated > verified so the
 * section badge always reflects the riskier of the two signals.
 */
function combineOutcomes(a: ProviderOutcome, b: ProviderOutcome): ProviderOutcome {
  const rank: Record<ProviderOutcome, number> = {
    denied: 3,
    unavailable: 2,
    not_evaluated: 1,
    verified: 0,
  };
  return rank[a] >= rank[b] ? a : b;
}

// ---------------------------------------------------------------------------
// Section: XRPL Preconditions
// ---------------------------------------------------------------------------

function XrplPreconditionsSection({ permit }: { permit: PermitResponse }) {
  const c = permit.bundle.constraints;
  const rows: Array<{ label: string; value: ReactNode }> = [];
  if (c.jurisdiction) {
    rows.push({ label: "Jurisdiction", value: c.jurisdiction });
  }
  if (typeof c.max_amount === "number") {
    rows.push({ label: "Max amount", value: c.max_amount });
  }
  if (typeof c.amount === "number") {
    const within = c.within_limit !== false;
    rows.push({
      label: "Requested amount",
      value: (
        <span className={within ? "textGood" : "textBad"}>
          {c.amount}
          {!within && " (over limit)"}
        </span>
      ),
    });
  }
  if (typeof c.trustline_required === "boolean") {
    rows.push({
      label: "Trustline required",
      value: c.trustline_required ? "Yes" : "No",
    });
  }
  if (typeof c.freeze_possible === "boolean") {
    rows.push({
      label: "Freeze possible",
      value: c.freeze_possible ? "Yes" : "No",
    });
  }
  if (typeof c.clawback_possible === "boolean") {
    rows.push({
      label: "Clawback possible",
      value: c.clawback_possible ? "Yes" : "No",
    });
  }
  if (c.allowed_counterparty) {
    rows.push({
      label: "Allowed counterparty",
      value: <span className="breakAll">{c.allowed_counterparty}</span>,
    });
  }
  // XRPL preconditions are policy-engine-derived constraints rather
  // than provider checks. We render them in the neutral "Configured"
  // state when at least one constraint is set, otherwise "Not Evaluated".
  const state: SectionState = rows.length > 0 ? "neutral" : "not_evaluated";
  return (
    <ControlSection
      title="XRPL Preconditions"
      state={state}
      testId="control-section-xrpl-preconditions"
    >
      {rows.map((r) => (
        <ControlRow key={r.label} label={r.label} value={r.value} />
      ))}
    </ControlSection>
  );
}

// ---------------------------------------------------------------------------
// Section: Settlement Verification
// ---------------------------------------------------------------------------

function SettlementSection({
  settlementResult,
}: {
  settlementResult: SettlementVerifyResponse | null;
}) {
  if (!settlementResult) {
    return (
      <ControlSection
        title="Settlement Verification"
        state="not_evaluated"
        outcomeLabelOverride="Not verified yet"
        testId="control-section-settlement"
      >
        <ControlRow
          label="Status"
          value={
            <span className="textMuted">
              Submit and verify a settled XRPL transaction to populate this
              section.
            </span>
          }
        />
      </ControlSection>
    );
  }
  const outcome = classifySettlement(settlementResult);
  const state = settlementSectionState(outcome);
  const artifact = settlementResult.proof_artifact;
  const txHash =
    nonEmptyString(settlementResult.tx_hash) ??
    nonEmptyString(artifact?.anchor_metadata?.tx_hash as string | undefined);
  const codes = settlementResult.reason_codes ?? [];
  const unavailable = unavailableReasonCodes(codes);
  return (
    <ControlSection
      title="Settlement Verification"
      state={state}
      outcomeLabelOverride={settlementOutcomeLabel(outcome)}
      provider={artifact?.module ?? "Settlement engine"}
      evidence={txHash}
      reasonCodes={codes}
      unavailableCodes={unavailable}
      testId="control-section-settlement"
    >
      <ControlRow
        label="Decision"
        value={
          <span
            className={
              state === "verified"
                ? "textGood"
                : state === "unavailable"
                ? "textWarn"
                : "textBad"
            }
          >
            {settlementResult.decision_result}
          </span>
        }
      />
      {artifact?.rule_version_used && (
        <ControlRow label="Rule version" value={artifact.rule_version_used} />
      )}
    </ControlSection>
  );
}
