import { useEffect, useState } from "react";

import { apiPost, describeError } from "../lib/api";
import StatusMessage from "./StatusMessage";
import PanelNumber from "./PanelNumber";
import { checkClass, checkSymbol } from "../lib/format";
import type { PermitResponse, VerifyResponse } from "../types/api";

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
            const passed = result.signature_valid && result.not_expired;
            const decisionResult =
              result.decision_result ?? permit?.proof_artifact?.decision_result;
            const reasonCodes =
              result.reason_codes ?? permit?.proof_artifact?.reason_codes;
            return (
              <div className="verifyResult" data-testid="permit-verification-result">
                <div
                  className={`verifyHeader ${passed ? "good" : "bad"}`}
                  data-testid="permit-verification-outcome"
                  data-passed={passed ? "true" : "false"}
                >
                  <span className={`verifyIcon ${passed ? "good" : "bad"}`}>
                    {passed ? "✔" : "✘"}
                  </span>
                  {passed ? "PASS" : "FAIL"}
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
                    const decision = decisionResult.toLowerCase();
                    const isPermit = decision === "permit" || decision === "allow";
                    return (
                      <div className="verifyRow">
                        <span className={checkClass(isPermit)}>
                          {checkSymbol(isPermit)}
                        </span>
                        <span className="summaryLabel">Decision result</span>
                        <span
                          className={`summaryValue${
                            isPermit ? " textGood" : " textBad"
                          }`}
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
                {reasonCodes && reasonCodes.length > 0 && (
                  <div className="reasonCodes">
                    <div className="reasonCodesTitle">Reason codes</div>
                    <div className="reasonCodesList">
                      {reasonCodes.map((rc) => (
                        <span key={rc} className="reasonCode">{rc}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })()}
        </>
      )}
    </section>
  );
}
