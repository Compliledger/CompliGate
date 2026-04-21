import { useState } from "react";

import { apiPost, describeError } from "../lib/api";
import { checkClass, checkSymbol } from "../lib/format";
import PanelNumber from "./PanelNumber";
import StatusMessage from "./StatusMessage";
import type { TrustlineCheckResponse } from "../types/api";

/**
 * TrustlineCheckPanel
 *
 * Self-contained panel that checks whether an XRPL address holds the
 * expected trustline. It owns its own input, loading, error, and result
 * state and renders a clear pass/fail header along with the four backend
 * output fields:
 *
 *   - trustline_exists
 *   - issuer
 *   - currency
 *   - raw_lines_checked
 *
 * Behavior is preserved from the inline implementation that previously
 * lived in `App.tsx`: Enter submits the form, the primary button is
 * disabled while loading or with an empty address, and Clear resets the
 * panel to its initial state.
 */





type Props = {
  /** Optional panel number rendered next to the title (matches App layout). */
  panelNumber?: number;
};

export default function TrustlineCheckPanel({ panelNumber }: Props) {
  const [address, setAddress] = useState("");
  const [result, setResult] = useState<TrustlineCheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function checkTrustline() {
    const trimmed = address.trim();
    if (!trimmed) return;
    setError(null);
    setResult(null);
    setLoading(true);

    try {
      const data = await apiPost<TrustlineCheckResponse>(
        "/v1/xrpl/trustline/check",
        { address: trimmed },
      );
      setResult(data);
    } catch (e: unknown) {
      setError(describeError(e, "Failed to check trustline."));
    } finally {
      setLoading(false);
    }
  }

  function clear() {
    setAddress("");
    setResult(null);
    setError(null);
  }

  const canSubmit = address.trim().length > 0 && !loading;

  return (
    <>
      <h2>
        {panelNumber !== undefined && <PanelNumber n={panelNumber} />}
        Check Trustline
      </h2>
      <p className="muted">
        Check whether an XRPL address currently has the expected trustline.
      </p>

      <label className="label">Account Address</label>
      <input
        className="input"
        value={address}
        onChange={(e) => setAddress(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && canSubmit) checkTrustline();
        }}
        placeholder="r..."
        spellCheck={false}
      />

      <div className="row">
        <button
          className="btn primary"
          onClick={checkTrustline}
          disabled={!canSubmit}
        >
          {loading ? "Checking…" : "Check Trustline"}
        </button>
        <button className="btn" onClick={clear}>
          Clear
        </button>
      </div>

      {loading && (
        <StatusMessage variant="loading" title="Checking trustline…">
          Querying the XRPL for current trustlines on this address.
        </StatusMessage>
      )}

      {!loading && !result && !error && (
        <StatusMessage variant="empty" title="No trustline check yet">
          Enter an XRPL address above and run a check to see results here.
        </StatusMessage>
      )}

      {result && (
        <div className="verifyResult">
          <div className={`verifyHeader ${result.trustline_exists ? "good" : "bad"}`}>
            <span className={`verifyIcon ${result.trustline_exists ? "good" : "bad"}`}>
              {result.trustline_exists ? "✔" : "✘"}
            </span>
            {result.trustline_exists ? "Trustline Found" : "Trustline Not Found"}
          </div>

          <div className="verifyRows">
            <div className="verifyRow">
              <span className={checkClass(result.trustline_exists)}>
                {checkSymbol(result.trustline_exists)}
              </span>
              <span className="summaryLabel">Trustline Exists</span>
              <span className="summaryValue">
                {result.trustline_exists ? "Yes" : "No"}
              </span>
            </div>
            <div className="verifyRow">
              <span className={checkClass(Boolean(result.issuer))}>
                {checkSymbol(Boolean(result.issuer))}
              </span>
              <span className="summaryLabel">Issuer</span>
              <span className="summaryValue commitValueMono breakAll">
                {result.issuer ?? "—"}
              </span>
            </div>
            <div className="verifyRow">
              <span className={checkClass(Boolean(result.currency))}>
                {checkSymbol(Boolean(result.currency))}
              </span>
              <span className="summaryLabel">Currency</span>
              <span className="summaryValue">{result.currency ?? "—"}</span>
            </div>
            <div className="verifyRow">
              <span className={checkClass(true)}>{checkSymbol(true)}</span>
              <span className="summaryLabel">Raw Lines Checked</span>
              <span className="summaryValue">{result.raw_lines_checked}</span>
            </div>
          </div>
        </div>
      )}

      {error && (
        <StatusMessage variant="error" title="Trustline check failed">
          {error}
        </StatusMessage>
      )}
    </>
  );
}
