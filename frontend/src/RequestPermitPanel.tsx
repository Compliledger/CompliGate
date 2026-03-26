import { useState, type KeyboardEvent } from "react";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

export type ProofArtifact = {
  module: string;
  entity_id: string;
  rule_version_used: string;
  decision_result: string;
  evaluation_context: Record<string, unknown>;
  reason_codes: string[];
  timestamp: number;
  bundle_hash: string;
  anchor_metadata: Record<string, unknown>;
};

export type PermitConstraints = {
  max_amount: number;
  allowed_counterparty?: string | null;
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
    policy_id: string;
  };
  constraints: PermitConstraints;
  policy: Record<string, unknown>;
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
  decision_result?: string;
  reason_codes?: string[];
};

type PermitRequestBody = {
  subject: string;
  action: string;
  amount?: number;
};

function extractErrorMessage(data: unknown, fallback: string): string {
  if (!data) return fallback;
  const d = data as Record<string, unknown>;
  const detail = d.detail;
  if (typeof detail === "string") return detail;
  if (typeof detail === "object" && detail !== null) {
    return (
      (detail as Record<string, string>).reason ??
      (detail as Record<string, string>).error ??
      JSON.stringify(detail)
    );
  }
  return fallback;
}

function PanelNumber({ n }: { n: number }) {
  return <span className="panelNumber">{n}</span>;
}

type Props = {
  onPermit: (permit: PermitResponse) => void;
  onClear: () => void;
};

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

      const res = await fetch(`${API_BASE}/v1/permit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      const data = await res.json();
      if (!res.ok) {
        setError(extractErrorMessage(data, "Failed to request permit."));
        return;
      }
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
      setError(e instanceof Error ? e.message : "Network error calling backend.");
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

      {error && <div className="alert bad">{error}</div>}
    </section>
  );
}
