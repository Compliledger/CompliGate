import { useState, type KeyboardEvent } from "react";

import { apiPost, describeError } from "../lib/api";
import { isDeniedDecision, unavailableReasonCodes } from "../lib/format";
import StatusMessage from "./StatusMessage";
import PanelNumber from "./PanelNumber";
import type { PermitResponse } from "../types/api";

type PermitRequestBody = {
  subject: string;
  action: string;
  amount?: number;
};

type Props = {
  onPermit: (permit: PermitResponse) => void;
  onClear: () => void;
};

/**
 * RequestPermitPanel
 *
 * Self-contained panel for requesting a time-bound compliance permit
 * from the backend. Owns its own form state (subject / action / amount)
 * and notifies the parent via `onPermit` / `onClear` callbacks so the
 * page-level orchestrator can react (e.g. resetting downstream state).
 */
export default function RequestPermitPanel({ onPermit, onClear }: Props) {
  const [subject, setSubject] = useState("");
  const [action, setAction] = useState("transfer");
  const [amount, setAmount] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [denial, setDenial] = useState<{
    decision: string;
    reasonCodes: string[];
    unavailable: string[];
  } | null>(null);

  async function requestPermit() {
    setError(null);
    setDenial(null);

    const trimmed = subject.trim();
    if (!trimmed) {
      setError("Enter an address to request a permit.");
      return;
    }

    const parsedAmount = amount.trim() ? parseFloat(amount.trim()) : undefined;
    if (parsedAmount !== undefined && (isNaN(parsedAmount) || !isFinite(parsedAmount))) {
      setError("Amount must be a valid number.");
      return;
    }

    setLoading(true);
    try {
      const body: PermitRequestBody = { subject: trimmed, action };
      if (parsedAmount !== undefined) body.amount = parsedAmount;

      const data = await apiPost<unknown>("/v1/permit", body);
      if (
        !data ||
        typeof data !== "object" ||
        !("bundle" in data) ||
        !("signature" in data) ||
        !("bundle_hash" in data)
      ) {
        setError("Unexpected response from server.");
        return;
      }
      const permit = data as PermitResponse;
      const decision =
        permit.decision_result ?? permit.proof_artifact?.decision_result;
      const reasonCodes =
        permit.reason_codes ?? permit.proof_artifact?.reason_codes ?? [];
      if (isDeniedDecision(decision) || permit.denied || permit.unavailable) {
        setDenial({
          decision: String(decision ?? "deny"),
          reasonCodes,
          unavailable: unavailableReasonCodes(reasonCodes),
        });
      }
      onPermit(permit);
    } catch (e: unknown) {
      setError(describeError(e, "Failed to request permit."));
    } finally {
      setLoading(false);
    }
  }

  function handleKeyDown(e: KeyboardEvent) {
    if (e.key === "Enter" && !loading && subject.trim()) {
      requestPermit();
    }
  }

  function handleClear() {
    setSubject("");
    setAction("transfer");
    setAmount("");
    setError(null);
    setDenial(null);
    onClear();
  }

  return (
    <section className="card" data-testid="request-permit-panel">
      <h2>
        <PanelNumber n={1} />
        Request Permit
      </h2>
      <p className="muted">
        Paste a subject address to request a time-bound compliance permit.
      </p>

      <label className="label">Subject Address</label>
      <input
        className="input"
        value={subject}
        onChange={(e) => setSubject(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="r..."
        spellCheck={false}
        data-testid="request-permit-subject"
      />

      <label className="label">Action</label>
      <select
        className="input"
        value={action}
        onChange={(e) => setAction(e.target.value)}
        data-testid="request-permit-action"
      >
        <option value="transfer">transfer</option>
        <option value="trustset">trustset</option>
      </select>

      <label className="label">Amount (optional)</label>
      <input
        className="input"
        type="text"
        inputMode="decimal"
        value={amount}
        onChange={(e) => setAmount(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="e.g. 100"
        data-testid="request-permit-amount"
      />

      <div className="row">
        <button
          className="btn primary"
          onClick={requestPermit}
          disabled={!subject.trim() || loading}
          data-testid="request-permit-submit"
        >
          {loading ? "Requesting…" : "Request Compliance Permit"}
        </button>
        <button className="btn" onClick={handleClear} data-testid="request-permit-clear">
          Clear
        </button>
      </div>

      {error && (
        <StatusMessage variant="error" title="Permit request failed">
          {error}
        </StatusMessage>
      )}
      {!error && loading && (
        <StatusMessage variant="loading" title="Requesting permit…">
          Contacting the CompliGate backend.
        </StatusMessage>
      )}
      {!error && !loading && denial && (
        <StatusMessage
          variant={denial.unavailable.length > 0 ? "warning" : "error"}
          title={
            denial.unavailable.length > 0
              ? "Permit denied — required compliance check unavailable"
              : "Permit denied"
          }
        >
          <div data-testid="request-permit-denial">
            {denial.unavailable.length > 0 ? (
              <p style={{ margin: "0 0 8px" }}>
                The backend failed closed because one or more required
                provider checks could not return a definitive result. No
                permit was issued for this request.
              </p>
            ) : (
              <p style={{ margin: "0 0 8px" }}>
                The backend denied this permit request. The reason codes
                below describe which controls blocked issuance.
              </p>
            )}
            {denial.reasonCodes.length > 0 && (
              <div className="reasonCodesList" data-testid="request-permit-denial-codes">
                {denial.reasonCodes.map((rc) => (
                  <span key={rc} className="reasonCode reasonCodeBad">
                    {rc}
                  </span>
                ))}
              </div>
            )}
          </div>
        </StatusMessage>
      )}
    </section>
  );
}
