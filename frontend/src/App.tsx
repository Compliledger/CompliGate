import { useEffect, useMemo, useState } from "react";
import "./App.css";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

type PermitBundle = {
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
  constraints: Record<string, unknown>;
  policy: Record<string, unknown>;
  attestations: Record<string, unknown>;
  scope: string[];
  nonce: string;
};

type PermitValidity = {
  single_use: boolean;
};

type PermitConstraints = {
  max_amount: number;
  allowed_counterparty?: string | null;
};

type PermitResponse = {
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
};

type VerifyResponse = {
  signature_valid: boolean;
  not_expired: boolean;
  subject?: string;
  policy_version?: string;
  action?: string;
  bundle_hash?: string;
  constraints?: PermitConstraints;
};

type CommitResponse = {
  committed: boolean;
  algorand_tx_id?: string;
  bundle_hash?: string;
};

type PermitRequestBody = {
  subject: string;
  action: string;
  amount?: number;
};

type AdapterHealth = {
  adapter_configured: boolean;
  reachable: boolean;
};

function formatSeconds(s: number) {
  const mm = Math.floor(s / 60);
  const ss = s % 60;
  return `${String(mm).padStart(2, "0")}:${String(ss).padStart(2, "0")}`;
}

function checkClass(valid: boolean) {
  return valid ? "check" : "check checkFail";
}

function checkSymbol(valid: boolean) {
  return valid ? "✔" : "✘";
}

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

function adapterConfiguredLabel(health: AdapterHealth | null): string {
  if (!health) return "Checking...";
  return health.adapter_configured ? "Configured" : "Not Configured";
}

function adapterReachableLabel(health: AdapterHealth | null): string {
  if (!health) return "Checking...";
  return health.reachable ? "Reachable" : "Unreachable";
}

function PanelNumber({ n }: { n: number }) {
  return <span className="panelNumber">{n}</span>;
}

export default function App() {
  const [subject, setSubject] = useState("");
  const [action, setAction] = useState("transfer");
  const [amount, setAmount] = useState("");
  const [permit, setPermit] = useState<PermitResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState<number>(() => Math.floor(Date.now() / 1000));
  const [verifyResult, setVerifyResult] = useState<VerifyResponse | null>(null);
  const [commitResult, setCommitResult] = useState<CommitResponse | null>(null);
  const [showTechnical, setShowTechnical] = useState(false);
  const [committing, setCommitting] = useState(false);
  const [adapterHealth, setAdapterHealth] = useState<AdapterHealth | null>(null);

  useEffect(() => {
    const t = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    fetch(`${API_BASE}/v1/adapter-health`)
      .then((r) => r.json())
      .then((d: AdapterHealth) => setAdapterHealth(d))
      .catch((err) => {
        console.error("Failed to fetch adapter health:", err);
        setAdapterHealth({ adapter_configured: false, reachable: false });
      });
  }, []);

  const remaining = useMemo(() => {
    if (!permit) return 0;
    return Math.max(0, permit.expires_at - now);
  }, [permit, now]);

  const status = useMemo(() => {
    if (commitResult) return { label: "Anchored", kind: "anchored" as const };
    if (!permit) return { label: "No Permit", kind: "neutral" as const };
    if (remaining <= 0) return { label: "Expired", kind: "bad" as const };
    if (remaining < 60) return { label: "Expiring Soon", kind: "warn" as const };
    return { label: "Active", kind: "good" as const };
  }, [permit, remaining, commitResult]);

  const permitActive = permit && remaining > 0;

  async function requestPermit() {
    setError(null);
    setPermit(null);
    setVerifyResult(null);
    setCommitResult(null);

    const trimmed = subject.trim();
    if (!trimmed) {
      setError("Enter an address to request a permit.");
      return;
    }

    const parsedAmount = amount.trim() ? parseFloat(amount.trim()) : undefined;
    if (parsedAmount !== undefined && isNaN(parsedAmount)) {
      setError("Amount must be a valid number.");
      return;
    }

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
      setPermit(data);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Network error calling backend.");
    }
  }

  async function verifyPermit() {
    if (!permit) return;
    setError(null);
    setVerifyResult(null);

    try {
      const res = await fetch(`${API_BASE}/v1/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ bundle: permit.bundle, signature: permit.signature }),
      });

      const data = await res.json();
      if (!res.ok) {
        setError(extractErrorMessage(data, "Failed to verify permit."));
        return;
      }
      setVerifyResult(data);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Network error calling verify endpoint.");
    }
  }

  async function commitToAlgorand() {
    if (!permit) return;
    setError(null);
    setCommitResult(null);
    setCommitting(true);

    try {
      const res = await fetch(`${API_BASE}/v1/commit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          bundle_hash: permit.bundle_hash,
          subject: permit.bundle.subject,
          policy_id: permit.bundle.asset.policy_id,
          exp: permit.bundle.exp,
          action: permit.bundle.action,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setError(extractErrorMessage(data, "Failed to commit to Algorand."));
      } else {
        setCommitResult(data);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Network error calling commit endpoint.");
    } finally {
      setCommitting(false);
    }
  }

  return (
    <div className="page">
      <header className="header">
        <div className="brand">
          <div className="title">
            <span className="titleAccent">Compli</span>Gate
          </div>
          <div className="subtitle">Compliance authorization infrastructure · MVP</div>
        </div>

        <div className={`pill ${status.kind}`}>
          <span className="dot" />
          {status.label}
          {permit && remaining > 0 && !commitResult && (
            <span className="pillRight">{formatSeconds(remaining)}</span>
          )}
        </div>
      </header>

      <div className="adapterBar">
        <span className="adapterBarLabel">Algorand Adapter</span>
        <span className={`badge ${adapterHealth?.adapter_configured ? "good" : "bad"}`}>
          <span className="badgeDot" />
          {adapterConfiguredLabel(adapterHealth)}
        </span>
        <span className={`badge ${adapterHealth?.reachable ? "good" : "bad"}`}>
          <span className="badgeDot" />
          {adapterReachableLabel(adapterHealth)}
        </span>
      </div>

      <main className="grid">
        {/* Panel 1: Request Permit */}
        <section className="card">
          <h2><PanelNumber n={1} />Request Permit</h2>
          <p className="muted">
            Paste a subject address to request a time-bound compliance permit.
          </p>

          <label className="label">Subject Address</label>
          <input
            className="input"
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
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
            type="number"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            placeholder="e.g. 100"
            min="0"
          />

          <div className="row">
            <button className="btn primary" onClick={requestPermit} disabled={!subject.trim()}>
              Request Permit
            </button>
            <button
              className="btn"
              onClick={() => {
                setPermit(null);
                setVerifyResult(null);
                setCommitResult(null);
                setError(null);
              }}
              disabled={!permit && !error && !commitResult}
            >
              Clear
            </button>
          </div>

          {error && <div className="alert bad">{error}</div>}
        </section>

        {/* Panel 2: Permit Summary */}
        <section className="card">
          <div className="summaryHeader">
            <h2><PanelNumber n={2} />Permit Summary</h2>
            <span className={`badge ${status.kind}`}>
              <span className="badgeDot" />
              {status.label}
            </span>
          </div>

          {!permit ? (
            <p className="muted">Request a permit to view the compliance summary.</p>
          ) : (
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
          )}
        </section>

        {/* Panel 3: Technical Proof */}
        <section className="card spanFull">
          <h2><PanelNumber n={3} />Technical Proof</h2>
          {!permit ? (
            <p className="muted">
              Proof bundle details will appear here after a permit is issued.
            </p>
          ) : (
            <div className="codeBlock">
              <div className="codeTitle">Bundle Hash (SHA-256)</div>
              <pre>{permit.bundle_hash}</pre>

              <div className="codeTitle">Proof Bundle</div>
              <pre>{JSON.stringify(permit.bundle, null, 2)}</pre>

              <div className="codeTitle">Signature</div>
              <pre>{permit.signature}</pre>
            </div>
          )}
        </section>

        {/* Panel 4: Verification */}
        <section className="card">
          <h2><PanelNumber n={4} />Verification</h2>
          <p className="muted">
            Verify the permit signature and confirm it has not expired.
          </p>

          <div className="row">
            <button className="btn primary" onClick={verifyPermit} disabled={!permit}>
              Verify Permit
            </button>
          </div>

          {verifyResult && (
            <div
              className={`alert ${
                verifyResult.signature_valid && verifyResult.not_expired ? "good" : "bad"
              }`}
            >
              <div><span className="muted">Signature valid:</span> <b>{String(verifyResult.signature_valid)}</b></div>
              <div><span className="muted">Not expired:</span> <b>{String(verifyResult.not_expired)}</b></div>
              {verifyResult.action && (
                <div><span className="muted">Action:</span> <b>{verifyResult.action}</b></div>
              )}
              {verifyResult.policy_version && (
                <div><span className="muted">Policy version:</span> <b>{verifyResult.policy_version}</b></div>
              )}
              {verifyResult.bundle_hash && (
                <div><span className="muted">Bundle hash:</span> <b style={{ wordBreak: "break-all" }}>{verifyResult.bundle_hash}</b></div>
              )}
            </div>
          )}
        </section>

        {/* Panel 5: Algorand Commit */}
        <section className="card">
          <h2><PanelNumber n={5} />Algorand Commit</h2>
          <p className="muted">
            Commit the proof bundle to the Algorand adapter for on-chain anchoring.
          </p>

          <div className="row">
            <button
              className="btn primary"
              onClick={commitToAlgorand}
              disabled={!permitActive || committing}
            >
              {committing ? "Committing…" : "Commit to Algorand"}
            </button>
          </div>

          {commitResult && (
            <div className="alert good">
              <span className="pill anchored pillInlineMargin">⚓ Anchored</span>
              Committed: <b>{String(commitResult.committed)}</b>
              {commitResult.algorand_tx_id && (
                <>&nbsp;|&nbsp;Algorand TX: <b>{commitResult.algorand_tx_id}</b></>
              )}
              {commitResult.bundle_hash && (
                <><br />Bundle Hash: <b style={{ wordBreak: "break-all" }}>{commitResult.bundle_hash}</b></>
              )}
            </div>
          )}
        </section>
      </main>

      <footer className="footer">
        <span className="muted">
          MVP · Permits are signed &amp; time-bound · On-chain enforcement is a future phase
        </span>
      </footer>
    </div>
  );
}
