import { useState, type KeyboardEvent } from "react";

import { apiPost, describeError } from "../lib/api";
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

  async function requestPermit() {
    setError(null);

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
      onPermit(data as PermitResponse);
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
    onClear();
  }

  return (
    <section className="card">
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
      />

      <label className="label">Action</label>
      <select
        className="input"
        value={action}
        onChange={(e) => setAction(e.target.value)}
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
      />

      <div className="row">
        <button
          className="btn primary"
          onClick={requestPermit}
          disabled={!subject.trim() || loading}
        >
          {loading ? "Requesting…" : "Request Compliance Permit"}
        </button>
        <button className="btn" onClick={handleClear}>
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
    </section>
  );
}
