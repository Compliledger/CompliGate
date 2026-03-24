import { useEffect, useMemo, useState } from "react";
import "./App.css";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

type PermitResponse = {
  summary: {
    issuer_verified: boolean;
    asset_classification: string;
    custody_attestation_bound: boolean;
    reserve_attestation_bound: boolean;
    policy_version: string;
    expires_in_seconds: number;
  };
  bundle: Record<string, unknown>;
  signature: string;
  signed_at: number;
  expires_at: number;
  expires_in_seconds: number;
  bundle_hash: string;
};

type VerifyResponse = {
  signature_valid: boolean;
  not_expired: boolean;
  subject?: string;
  policy_version?: string;
  action?: string;
  bundle_hash?: string;
};

type CommitResponse = {
  status: string;
  tx_id?: string;
};

function formatSeconds(s: number) {
  const mm = Math.floor(s / 60);
  const ss = s % 60;
  return `${String(mm).padStart(2, "0")}:${String(ss).padStart(2, "0")}`;
}

export default function App() {
  const [subject, setSubject] = useState("");
  const [permit, setPermit] = useState<PermitResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState<number>(() => Math.floor(Date.now() / 1000));
  const [verifyResult, setVerifyResult] = useState<VerifyResponse | null>(null);
  const [commitResult, setCommitResult] = useState<CommitResponse | null>(null);
  const [committing, setCommitting] = useState(false);

  useEffect(() => {
    const t = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(t);
  }, []);

  const remaining = useMemo(() => {
    if (!permit) return 0;
    return Math.max(0, permit.expires_at - now);
  }, [permit, now]);

  const status = useMemo(() => {
    if (!permit) return { label: "No Permit", kind: "neutral" as const };
    if (remaining <= 0) return { label: "Expired", kind: "bad" as const };
    if (remaining < 60) return { label: "Expiring Soon", kind: "warn" as const };
    return { label: "Active", kind: "good" as const };
  }, [permit, remaining]);

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

    try {
      const res = await fetch(`${API_BASE}/v1/permit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ subject: trimmed }),
      });

      const data = await res.json();
      if (!res.ok) {
        setError(data?.detail ?? "Failed to request permit.");
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
        setError(data?.detail ?? "Failed to verify permit.");
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
        body: JSON.stringify({ bundle: permit.bundle, signature: permit.signature }),
      });

      const data = await res.json();
      if (!res.ok) {
        setError(data?.detail ?? "Failed to commit to Algorand.");
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
          <div className="title">CompliGate</div>
          <div className="subtitle">Compliance authorization infrastructure (MVP)</div>
        </div>

        <div className={`pill ${status.kind}`}>
          <span className="dot" />
          {status.label}
          {permit && (
            <span className="pillRight">
              {remaining > 0 ? formatSeconds(remaining) : "00:00"}
            </span>
          )}
        </div>
      </header>

      <main className="grid">
        {/* Panel 1: Wallet / Request Permit */}
        <section className="card">
          <h2>Wallet / Request Permit</h2>
          <p className="muted">
            Paste a subject address to request a time-bound compliance permit.
            Wallet connect coming in a later phase.
          </p>

          <label className="label">Subject Address</label>
          <input
            className="input"
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            placeholder="r..."
            spellCheck={false}
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
              disabled={!permit && !error}
            >
              Clear
            </button>
          </div>

          {error && <div className="alert bad">{error}</div>}
        </section>

        {/* Panel 2: Permit Summary */}
        <section className="card">
          <h2>Permit Summary</h2>
          {!permit ? (
            <p className="muted">Request a permit to view the compliance summary.</p>
          ) : (
            <div className="summary">
              <div className="item">
                <span className="check">✔</span> Issuer verified
              </div>
              <div className="item">
                <span className="check">✔</span> Asset:{" "}
                <b>{permit.summary.asset_classification}</b>
              </div>
              <div className="item">
                <span className="check">✔</span> Custody attestation bound
              </div>
              <div className="item">
                <span className="check">✔</span> Reserve attestation bound
              </div>
              <div className="item">
                <span className="check">✔</span> Policy:{" "}
                <b>{permit.summary.policy_version}</b>
              </div>
              {!permitActive && (
                <div className="alert warn">Permit expired. Request a new permit.</div>
              )}
            </div>
          )}
        </section>

        {/* Panel 3: Technical Proof */}
        <section className="card spanFull">
          <h2>Technical Proof</h2>
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
          <h2>Verification</h2>
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
          <h2>Algorand Commit</h2>
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
              Committed — status: <b>{commitResult.status}</b>
              {commitResult.tx_id && (
                <>&nbsp;|&nbsp;tx_id: <b>{commitResult.tx_id}</b></>
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
