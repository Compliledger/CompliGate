import { useMemo } from "react";

import StatusMessage from "./StatusMessage";
import { checkClass, checkSymbol, formatSeconds } from "../lib/format";
import type {
  BaseComplianceCheckResult,
  PermitResponse,
  SanctionsCheckResult,
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
  /** Optional CSS flex order, used to position among sibling panels. */
  order?: number;
};

/**
 * Returns true when a normalized compliance check result represents a
 * passing/allowing outcome. Used to coerce the widened
 * `boolean | <CheckResult>` constraint fields into the boolean shape
 * `checkClass`/`checkSymbol` expect, without changing rendered behavior
 * for the legacy primitive form.
 */
function isCheckPassing(
  value: boolean | BaseComplianceCheckResult | undefined,
): boolean {
  if (typeof value === "boolean") return value;
  if (!value) return false;
  if (value.decision) return value.decision === "allow";
  return value.status === "pass";
}

/**
 * Display string for the legacy `sanctions_check` field, which historically
 * was a plain string (e.g. "passed") but may now arrive as a normalized
 * `SanctionsCheckResult`.
 */
function sanctionsLabel(value: string | SanctionsCheckResult | undefined): string {
  if (!value) return "";
  if (typeof value === "string") return value;
  return value.decision ?? value.status;
}

function isSanctionsPassing(
  value: string | SanctionsCheckResult | undefined,
): boolean {
  if (!value) return false;
  if (typeof value === "string") return value === "passed";
  if (value.decision) return value.decision === "allow";
  return value.status === "pass";
}

/**
 * PermitSummaryPanel
 *
 * Renders the "Permit Constraints Snapshot" card: a compact overview of
 * issuer / asset / custody / reserve attestation flags plus the XRPL /
 * RLUSD regulatory controls and an expiry progress bar.
 *
 * Pure presentation: receives the permit and derived header status from
 * its parent so the page-level orchestrator can keep the canonical
 * permit state.
 */
export default function PermitSummaryPanel({ permit, status, remaining, order }: Props) {
  const expiryPercent = useMemo(() => {
    if (!permit || remaining <= 0 || permit.expires_in_seconds <= 0) return 0;
    return Math.min(100, (remaining / permit.expires_in_seconds) * 100);
  }, [permit, remaining]);

  return (
    <section className="card" style={order !== undefined ? { order } : undefined}>
      <div className="summaryHeader">
        <h2>Permit Constraints Snapshot</h2>
        <span className={`badge ${status.kind}`}>
          <span className="badgeDot" />
          {status.label}
        </span>
      </div>

      {!permit ? (
        <StatusMessage variant="empty" title="No permit yet">
          Request a permit to view the constraints.
        </StatusMessage>
      ) : (
        <>
          <div className="summary">
            <div className="summaryRow">
              <span className={checkClass(permit.summary.issuer_verified)}>
                {checkSymbol(permit.summary.issuer_verified)}
              </span>
              <span className="summaryLabel">Issuer verified</span>
              <span className="summaryValue">
                {permit.summary.issuer_verified ? "Yes" : "No"}
              </span>
            </div>
            <div className="summaryRow">
              <span className="check">✔</span>
              <span className="summaryLabel">Asset classification</span>
              <span className="summaryValue">{permit.summary.asset_classification}</span>
            </div>
            {permit.bundle.asset.regulatory_treatment && (
              <div className="summaryRow">
                <span className="check">✔</span>
                <span className="summaryLabel">Regulatory treatment</span>
                <span className="summaryValue">{permit.bundle.asset.regulatory_treatment}</span>
              </div>
            )}
            <div className="summaryRow">
              <span className={checkClass(permit.summary.custody_attestation_bound)}>
                {checkSymbol(permit.summary.custody_attestation_bound)}
              </span>
              <span className="summaryLabel">Custody attestation</span>
              <span className="summaryValue">
                {permit.summary.custody_attestation_bound ? "Bound" : "Unbound"}
              </span>
            </div>
            <div className="summaryRow">
              <span className={checkClass(permit.summary.reserve_attestation_bound)}>
                {checkSymbol(permit.summary.reserve_attestation_bound)}
              </span>
              <span className="summaryLabel">Reserve attestation</span>
              <span className="summaryValue">
                {permit.summary.reserve_attestation_bound ? "Bound" : "Unbound"}
              </span>
            </div>
            <div className="summaryRow">
              <span className="check">✔</span>
              <span className="summaryLabel">Policy version</span>
              <span className="summaryValue">{permit.summary.policy_version}</span>
            </div>
            <div className="summaryRow">
              <span
                className={`check${
                  remaining <= 0
                    ? " checkFail"
                    : remaining < 60
                    ? " checkWarn"
                    : ""
                }`}
              >
                {remaining > 0 ? "⏱" : "✘"}
              </span>
              <span className="summaryLabel">Expires in</span>
              <span
                className={`summaryValue${
                  remaining <= 0
                    ? " textBad"
                    : remaining < 60
                    ? " textWarn"
                    : ""
                }`}
              >
                {remaining > 0 ? formatSeconds(remaining) : "Expired"}
              </span>
            </div>
          </div>

          <div className="regulatoryControlsHeader">XRPL / RLUSD Regulatory Controls</div>
          <div className="summary">
            {permit.bundle.constraints.reserve_backed !== undefined && (
              <div className="summaryRow">
                <span className={checkClass(isCheckPassing(permit.bundle.constraints.reserve_backed))}>
                  {checkSymbol(isCheckPassing(permit.bundle.constraints.reserve_backed))}
                </span>
                <span className="summaryLabel">Reserve backed</span>
                <span className="summaryValue">
                  {isCheckPassing(permit.bundle.constraints.reserve_backed) ? "Yes" : "No"}
                </span>
              </div>
            )}
            {permit.bundle.constraints.liquidity_verified !== undefined && (
              <div className="summaryRow">
                <span className={checkClass(isCheckPassing(permit.bundle.constraints.liquidity_verified))}>
                  {checkSymbol(isCheckPassing(permit.bundle.constraints.liquidity_verified))}
                </span>
                <span className="summaryLabel">Liquidity verified</span>
                <span className="summaryValue">
                  {isCheckPassing(permit.bundle.constraints.liquidity_verified) ? "Yes" : "No"}
                </span>
              </div>
            )}
            {permit.bundle.constraints.kyc_verified !== undefined && (
              <div className="summaryRow">
                <span className={checkClass(isCheckPassing(permit.bundle.constraints.kyc_verified))}>
                  {checkSymbol(isCheckPassing(permit.bundle.constraints.kyc_verified))}
                </span>
                <span className="summaryLabel">KYC verified</span>
                <span className="summaryValue">
                  {isCheckPassing(permit.bundle.constraints.kyc_verified) ? "Yes" : "No"}
                </span>
              </div>
            )}
            {permit.bundle.constraints.sanctions_check !== undefined && (
              <div className="summaryRow">
                <span className={checkClass(isSanctionsPassing(permit.bundle.constraints.sanctions_check))}>
                  {checkSymbol(isSanctionsPassing(permit.bundle.constraints.sanctions_check))}
                </span>
                <span className="summaryLabel">Sanctions check</span>
                <span className="summaryValue">{sanctionsLabel(permit.bundle.constraints.sanctions_check)}</span>
              </div>
            )}
            {permit.bundle.constraints.jurisdiction && (
              <div className="summaryRow">
                <span className="check">✔</span>
                <span className="summaryLabel">Jurisdiction</span>
                <span className="summaryValue">{permit.bundle.constraints.jurisdiction}</span>
              </div>
            )}
            {permit.bundle.constraints.max_amount !== undefined && (
              <div className="summaryRow">
                <span className="check">✔</span>
                <span className="summaryLabel">Max amount</span>
                <span className="summaryValue">{permit.bundle.constraints.max_amount}</span>
              </div>
            )}
            {permit.bundle.constraints.freeze_possible !== undefined && (
              <div className="summaryRow">
                <span className={checkClass(permit.bundle.constraints.freeze_possible)}>
                  {checkSymbol(permit.bundle.constraints.freeze_possible)}
                </span>
                <span className="summaryLabel">Freeze possible</span>
                <span className="summaryValue">
                  {permit.bundle.constraints.freeze_possible ? "Yes" : "No"}
                </span>
              </div>
            )}
            {permit.bundle.constraints.clawback_possible !== undefined && (
              <div className="summaryRow">
                <span className={checkClass(permit.bundle.constraints.clawback_possible)}>
                  {checkSymbol(permit.bundle.constraints.clawback_possible)}
                </span>
                <span className="summaryLabel">Clawback possible</span>
                <span className="summaryValue">
                  {permit.bundle.constraints.clawback_possible ? "Yes" : "No"}
                </span>
              </div>
            )}
            {permit.bundle.constraints.trustline_required !== undefined && (
              <div className="summaryRow">
                <span className={checkClass(permit.bundle.constraints.trustline_required)}>
                  {checkSymbol(permit.bundle.constraints.trustline_required)}
                </span>
                <span className="summaryLabel">Trustline required</span>
                <span className="summaryValue">
                  {permit.bundle.constraints.trustline_required ? "Yes" : "No"}
                </span>
              </div>
            )}
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
