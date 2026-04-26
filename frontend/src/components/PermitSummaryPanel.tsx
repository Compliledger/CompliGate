import { useMemo } from "react";

import StatusMessage from "./StatusMessage";
import {
  checkClass,
  checkSymbol,
  formatSeconds,
  formatStatusLabel,
  isDeniedDecision,
  outcomeClass,
  outcomeSymbol,
  outcomeTextClass,
  providerOutcome,
  unavailableReasonCodes,
} from "../lib/format";
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
                      ? "The backend failed closed because one or more required provider checks could not return a definitive result. The constraints below reflect the unverified state and must not be treated as a passing compliance outcome."
                      : "The backend denied this permit. The constraints below reflect the unverified state and must not be treated as a passing compliance outcome."}
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
          <div className="summary">
            <div className="summaryRow">
              <span className={checkClass(permit.summary.issuer_verified)}>
                {checkSymbol(permit.summary.issuer_verified)}
              </span>
              <span className="summaryLabel">Issuer configured</span>
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

          <div className="regulatoryControlsHeader">Provider-Backed Compliance Checks</div>
          <div className="summary">
            {(() => {
              const kycOutcome = providerOutcome(permit.summary.kyc_status);
              const kycResult = permit.bundle.attestations.kyc_result;
              const kycReference = permit.bundle.attestations.kyc_reference;
              return (
                <div className="summaryRow">
                  <span className={outcomeClass(kycOutcome)}>
                    {outcomeSymbol(kycOutcome)}
                  </span>
                  <span className="summaryLabel">
                    KYC
                    {(kycResult?.provider_name || kycReference) && (
                      <span className="evidenceMeta">
                        {kycResult?.provider_name && (
                          <>
                            <span className="evidenceMetaLabel">Provider</span>
                            {kycResult.provider_name}
                          </>
                        )}
                        {kycReference && (
                          <>
                            {kycResult?.provider_name ? " · " : ""}
                            <span className="evidenceMetaLabel">Ref</span>
                            {kycReference}
                          </>
                        )}
                      </span>
                    )}
                  </span>
                  <span className={`summaryValue ${outcomeTextClass(kycOutcome)}`}>
                    {formatStatusLabel(permit.summary.kyc_status)}
                  </span>
                </div>
              );
            })()}
            {(() => {
              const sanctionsOutcome = providerOutcome(permit.summary.sanctions_status);
              const sanctionsReference = permit.bundle.attestations.sanctions_reference;
              const sanctionsProvider = permit.bundle.compliance_evidence?.find(
                (e) => e.check === "sanctions",
              )?.provider_id;
              return (
                <div className="summaryRow">
                  <span className={outcomeClass(sanctionsOutcome)}>
                    {outcomeSymbol(sanctionsOutcome)}
                  </span>
                  <span className="summaryLabel">
                    Sanctions screening
                    {(sanctionsProvider || sanctionsReference) && (
                      <span className="evidenceMeta">
                        {sanctionsProvider && (
                          <>
                            <span className="evidenceMetaLabel">Provider</span>
                            {sanctionsProvider}
                          </>
                        )}
                        {sanctionsReference && (
                          <>
                            {sanctionsProvider ? " · " : ""}
                            <span className="evidenceMetaLabel">Ref</span>
                            {sanctionsReference}
                          </>
                        )}
                      </span>
                    )}
                  </span>
                  <span className={`summaryValue ${outcomeTextClass(sanctionsOutcome)}`}>
                    {formatStatusLabel(permit.summary.sanctions_status)}
                  </span>
                </div>
              );
            })()}
            {(() => {
              const reserveOutcome = providerOutcome(permit.summary.reserve_status);
              const reserveResult = permit.bundle.attestations.reserve_result;
              const reserveReference = permit.bundle.attestations.reserve_reference;
              return (
                <div className="summaryRow">
                  <span className={outcomeClass(reserveOutcome)}>
                    {outcomeSymbol(reserveOutcome)}
                  </span>
                  <span className="summaryLabel">
                    Reserve backing
                    {(reserveResult?.provider_name || reserveReference) && (
                      <span className="evidenceMeta">
                        {reserveResult?.provider_name && (
                          <>
                            <span className="evidenceMetaLabel">Attestor</span>
                            {reserveResult.provider_name}
                          </>
                        )}
                        {reserveReference && (
                          <>
                            {reserveResult?.provider_name ? " · " : ""}
                            <span className="evidenceMetaLabel">Ref</span>
                            {reserveReference}
                          </>
                        )}
                      </span>
                    )}
                  </span>
                  <span className={`summaryValue ${outcomeTextClass(reserveOutcome)}`}>
                    {formatStatusLabel(permit.summary.reserve_status)}
                  </span>
                </div>
              );
            })()}
            {(() => {
              const liquidityOutcome = providerOutcome(permit.summary.liquidity_status);
              const reserveResult = permit.bundle.attestations.reserve_result;
              const liquidityReference = permit.bundle.attestations.liquidity_reference;
              return (
                <div className="summaryRow">
                  <span className={outcomeClass(liquidityOutcome)}>
                    {outcomeSymbol(liquidityOutcome)}
                  </span>
                  <span className="summaryLabel">
                    Liquidity
                    {(reserveResult?.provider_name || liquidityReference) && (
                      <span className="evidenceMeta">
                        {reserveResult?.provider_name && (
                          <>
                            <span className="evidenceMetaLabel">Attestor</span>
                            {reserveResult.provider_name}
                          </>
                        )}
                        {liquidityReference && (
                          <>
                            {reserveResult?.provider_name ? " · " : ""}
                            <span className="evidenceMetaLabel">Ref</span>
                            {liquidityReference}
                          </>
                        )}
                      </span>
                    )}
                  </span>
                  <span className={`summaryValue ${outcomeTextClass(liquidityOutcome)}`}>
                    {formatStatusLabel(permit.summary.liquidity_status)}
                  </span>
                </div>
              );
            })()}
          </div>

          <div className="regulatoryControlsHeader">XRPL / RLUSD Issuer Controls</div>
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
