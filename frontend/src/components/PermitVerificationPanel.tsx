import { useEffect, useState } from "react";

import { apiPost, describeError } from "../lib/api";
import StatusMessage from "./StatusMessage";
import PanelNumber from "./PanelNumber";
import ProviderStatusSummary from "./ProviderStatusSummary";
import {
  checkClass,
  checkSymbol,
  formatStatusLabel,
  isDeniedDecision,
  outcomeClass,
  outcomeSymbol,
  outcomeTextClass,
  providerOutcome,
  unavailableReasonCodes,
  type ProviderOutcome,
} from "../lib/format";
import type {
  PermitResponse,
  ProviderStatusValue,
  VerifyResponse,
} from "../types/api";

type Props = {
  permit: PermitResponse | null;
  /** Optional panel number rendered next to the title. */
  panelNumber?: number;
  /** Optional CSS flex order, used to position among sibling panels. */
  order?: number;
};

/**
 * PermitVerificationPanel
 *
 * Self-contained panel that re-verifies the active permit's signature
 * against the backend. Owns its own loading / result / error state and
 * resets the displayed result whenever the parent supplies a new permit
 * (or clears it).
 */
export default function PermitVerificationPanel({ permit, panelNumber, order }: Props) {
  const [result, setResult] = useState<VerifyResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Reset displayed verification result whenever the active permit
  // changes (e.g. user requests a new permit or clears it).
  useEffect(() => {
    setResult(null);
    setError(null);
  }, [permit]);

  async function verifyPermit() {
    if (!permit) return;
    setError(null);
    setResult(null);
    setLoading(true);

    try {
      const data = await apiPost<unknown>("/v1/verify", {
        bundle: permit.bundle,
        signature: permit.signature,
      });
      if (
        !data ||
        typeof data !== "object" ||
        typeof (data as Record<string, unknown>).signature_valid !== "boolean" ||
        typeof (data as Record<string, unknown>).not_expired !== "boolean"
      ) {
        setError("Unexpected response from server.");
        return;
      }
      setResult(data as VerifyResponse);
    } catch (e: unknown) {
      setError(describeError(e, "Failed to verify permit."));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="card" style={order !== undefined ? { order } : undefined} data-testid="permit-verification-panel">
      <h2>
        {panelNumber !== undefined && <PanelNumber n={panelNumber} />}
        Verify Permit Signature
      </h2>
      {!permit ? (
        <StatusMessage variant="empty" title="No permit to verify">
          Request a permit to verify its signature here.
        </StatusMessage>
      ) : (
        <>
          <div className="row" style={{ marginTop: 0 }}>
            <button
              className="btn primary"
              onClick={verifyPermit}
              disabled={loading}
              data-testid="permit-verification-submit"
            >
              {loading ? "Verifying…" : "Verify Permit Signature"}
            </button>
          </div>

          {error && (
            <StatusMessage variant="error" title="Permit verification failed">
              {error}
            </StatusMessage>
          )}
          {result && (() => {
            const cryptographicallyValid =
              result.signature_valid && result.not_expired;
            const decisionResult =
              result.decision_result ?? permit?.proof_artifact?.decision_result;
            const reasonCodes =
              result.reason_codes ?? permit?.proof_artifact?.reason_codes ?? [];
            const decisionLower = decisionResult?.toLowerCase();
            const decisionPositive =
              decisionLower === "allow" ||
              decisionLower === "permit" ||
              decisionLower === "approved";
            const decisionDenied = isDeniedDecision(decisionResult);
            const unavailableCodes = unavailableReasonCodes(reasonCodes);
            // A permit is "compliance-denied" when the backend explicitly
            // signalled a deny on either the verify response or the issued
            // permit, or when the decision_result itself is a denial that is
            // not merely an "unavailable" outcome.
            const complianceDenied =
              Boolean(result.denied) ||
              Boolean(permit?.denied) ||
              (decisionDenied && decisionLower !== "unavailable");
            // A permit is "compliance-unavailable" when an explicit
            // unavailable signal is present, the decision itself is
            // "unavailable", or any reason code ends in `_UNAVAILABLE`.
            const complianceUnavailable =
              Boolean(result.unavailable) ||
              Boolean(permit?.unavailable) ||
              decisionLower === "unavailable" ||
              unavailableCodes.length > 0;
            // Whether we have *any* compliance context to evaluate. Without
            // a decision and without any deny/unavailable signal we cannot
            // claim the authorization is positive — we only know the
            // signature itself is intact.
            const hasComplianceContext =
              Boolean(decisionResult) ||
              complianceDenied ||
              complianceUnavailable ||
              Boolean(permit?.summary);

            // PASS only when the overall authorization decision is actually
            // positive. A valid signature on its own is never a PASS.
            const passed =
              cryptographicallyValid &&
              hasComplianceContext &&
              decisionPositive &&
              !complianceDenied &&
              !complianceUnavailable;

            // FAIL when the signature itself is broken/expired, or the
            // backend explicitly denied the authorization.
            const failed = !cryptographicallyValid || complianceDenied;

            // Otherwise (signature valid, but compliance unavailable / no
            // positive decision) the result is inconclusive — render as
            // WARN so it visually separates from a true PASS.
            const outcome: "pass" | "fail" | "warn" = passed
              ? "pass"
              : failed
              ? "fail"
              : "warn";
            const outcomeLabelText =
              outcome === "pass"
                ? "PASS"
                : outcome === "fail"
                ? "FAIL"
                : "INCONCLUSIVE";
            const outcomeIcon =
              outcome === "pass" ? "✔" : outcome === "fail" ? "✘" : "!";

            // Surface a clear callout when the signature is cryptographically
            // valid but compliance was unavailable or denied — the
            // distinction the requirement explicitly calls out.
            const distinctionMessage =
              cryptographicallyValid && complianceDenied
                ? {
                    variant: "error" as const,
                    title: "Signature valid, but authorization denied",
                    body:
                      "The bundle signature is cryptographically valid and the permit has not expired, but the policy engine denied this authorization. A valid signature is not the same as a compliant authorization.",
                  }
                : cryptographicallyValid && complianceUnavailable
                ? {
                    variant: "warning" as const,
                    title:
                      "Signature valid, but compliance checks unavailable",
                    body:
                      "The bundle signature is cryptographically valid and the permit has not expired, but one or more required compliance checks could not return a definitive result. Do not treat this as a passing authorization.",
                  }
                : cryptographicallyValid &&
                  !decisionPositive &&
                  !decisionResult
                ? {
                    variant: "warning" as const,
                    title:
                      "Signature valid, but no authorization decision available",
                    body:
                      "The bundle signature is cryptographically valid, but no authorization decision is associated with this permit. A valid signature alone is not a compliant authorization.",
                  }
                : null;

            // Provider-backed status summaries (rendered if returned with
            // the active permit).
            const providerStatuses: Array<{
              key: string;
              label: string;
              status: ProviderStatusValue | undefined;
            }> = permit
              ? [
                  {
                    key: "kyc",
                    label: "KYC",
                    status: permit.summary?.kyc_status,
                  },
                  {
                    key: "sanctions",
                    label: "Sanctions screening",
                    status: permit.summary?.sanctions_status,
                  },
                  {
                    key: "reserve",
                    label: "Reserve backing",
                    status: permit.summary?.reserve_status,
                  },
                  {
                    key: "liquidity",
                    label: "Liquidity",
                    status: permit.summary?.liquidity_status,
                  },
                ].filter((row) => row.status !== undefined)
              : [];

            return (
              <div className="verifyResult" data-testid="permit-verification-result">
                <div
                  className={`verifyHeader ${outcome}`}
                  data-testid="permit-verification-outcome"
                  data-passed={passed ? "true" : "false"}
                  data-outcome={outcome}
                >
                  <span className={`verifyIcon ${outcome}`}>
                    {outcomeIcon}
                  </span>
                  {outcomeLabelText}
                </div>
                <div className="verifyRows">
                  <div className="verifyRow">
                    <span className={checkClass(result.signature_valid)}>
                      {checkSymbol(result.signature_valid)}
                    </span>
                    <span className="summaryLabel">Signature valid</span>
                    <span className="summaryValue">{String(result.signature_valid)}</span>
                  </div>
                  <div className="verifyRow">
                    <span className={checkClass(result.not_expired)}>
                      {checkSymbol(result.not_expired)}
                    </span>
                    <span className="summaryLabel">Not expired</span>
                    <span className="summaryValue">{String(result.not_expired)}</span>
                  </div>
                  {decisionResult && (() => {
                    // Map the decision string onto the four-state
                    // outcome so the row's icon, value class, and label
                    // are all driven by the same shared pattern as the
                    // provider-backed compliance rows. An `unavailable`
                    // decision must render with the dash glyph and
                    // warn colour — never with the same ✘ + textBad
                    // styling as a hard deny.
                    const decisionOutcome: ProviderOutcome = decisionPositive
                      ? "verified"
                      : complianceUnavailable
                      ? "unavailable"
                      : complianceDenied || decisionDenied
                      ? "denied"
                      : "not_evaluated";
                    return (
                      <div
                        className="verifyRow"
                        data-testid="permit-verification-decision"
                      >
                        <span className={outcomeClass(decisionOutcome)}>
                          {outcomeSymbol(decisionOutcome)}
                        </span>
                        <span className="summaryLabel">Decision result</span>
                        <span
                          className={`summaryValue ${outcomeTextClass(decisionOutcome)}`}
                        >
                          {decisionResult}
                        </span>
                      </div>
                    );
                  })()}
                  {result.action && (
                    <div className="verifyRow">
                      <span className="check">✔</span>
                      <span className="summaryLabel">Action</span>
                      <span className="summaryValue">{result.action}</span>
                    </div>
                  )}
                  {result.policy_version && (
                    <div className="verifyRow">
                      <span className="check">✔</span>
                      <span className="summaryLabel">Policy version</span>
                      <span className="summaryValue">{result.policy_version}</span>
                    </div>
                  )}
                  {result.bundle_hash && (
                    <div className="verifyRow">
                      <span className="check">✔</span>
                      <span className="summaryLabel">Bundle hash</span>
                      <span className="summaryValue breakAll">{result.bundle_hash}</span>
                    </div>
                  )}
                </div>
                {distinctionMessage && (
                  <div style={{ padding: "10px 14px 4px" }}>
                    <StatusMessage
                      variant={distinctionMessage.variant}
                      title={distinctionMessage.title}
                    >
                      <span data-testid="permit-verification-distinction">
                        {distinctionMessage.body}
                      </span>
                    </StatusMessage>
                  </div>
                )}
                {providerStatuses.length > 0 && (
                  <div
                    className="verifyRows"
                    data-testid="permit-verification-provider-statuses"
                  >
                    <div
                      className="summaryLabel"
                      style={{ padding: "8px 0 4px", fontWeight: 600 }}
                    >
                      Provider-Backed Compliance Summary
                    </div>
                    {providerStatuses.map((row) => {
                      const o = providerOutcome(row.status);
                      return (
                        <div className="verifyRow" key={row.key}>
                          <span className={outcomeClass(o)}>
                            {outcomeSymbol(o)}
                          </span>
                          <span className="summaryLabel">{row.label}</span>
                          <span
                            className={`summaryValue ${outcomeTextClass(o)}`}
                          >
                            {formatStatusLabel(row.status)}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                )}
                {reasonCodes && reasonCodes.length > 0 && (
                  <div className="reasonCodes">
                    <div className="reasonCodesTitle">Reason codes</div>
                    <div className="reasonCodesList">
                      {reasonCodes.map((rc) => (
                        <span
                          key={rc}
                          className={`reasonCode ${
                            unavailableCodes.includes(rc)
                              ? "reasonCodeWarn"
                              : complianceDenied
                              ? "reasonCodeBad"
                              : ""
                          }`}
                        >
                          {rc}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                <ProviderStatusSummary permit={permit} />
              </div>
            );
          })()}
        </>
      )}
    </section>
  );
}
