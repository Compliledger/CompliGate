import { useEffect, useMemo, useState } from "react";
import "./App.css";

type PermitResponse = {
  summary: {
    issuer_verified: boolean;
    asset_classification: string;
    custody_attestation_bound: boolean;
    reserve_attestation_bound: boolean;
    policy_version: string;
    expires_in_seconds: number;
  };
  bundle: Record<string, any>;
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
  const [showTechnical, setShowTechnical] = useState(false);
  const [verifyResult, setVerifyResult] = useState<VerifyResponse | null>(null);

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
    setShowTechnical(false);

    const trimmed = subject.trim();
    if (!trimmed) {
      setError("Enter an XRPL address to request a permit.");
      return;
    }

    try {
      const res = await fetch("http://localhost:8000/v1/permit", {
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
    } catch (e: any) {
      setError(e?.message ?? "Network error calling backend.");
    }
  }

  async function verifyPermit() {
    if (!permit) return;

    setError(null);
    setVerifyResult(null);

    try {
      const res = await fetch("http://localhost:8000/v1/verify", {
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
    } catch (e: any) {
      setError(e?.message ?? "Network error calling verify endpoint.");
    }
  }

  return (
    <div className="page">
      <header className="header">
        <div className="brand">
          <div className="title">CompliGate</div>
          <div className="subtitle">Permissioned RLUSD authorization on XRPL (MVP)</div>
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
        {/* Wallet / Subject */}
        <section className="card">
          <h2>Wallet</h2>
          <p className="muted">
            For MVP, paste an XRPL address (later we’ll add wallet connect).
          </p>

          <label className="label">XRPL Address</label>
          <input
            className="input"
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            placeholder="r..."
            spellCheck={false}
          />

          <div className="row">
            <button className="btn primary" onClick={requestPermit} disabled={!subject.trim()}>
              Request Compliance Permit
            </button>
            <button
              className="btn"
              onClick={() => {
                setPermit(null);
                setVerifyResult(null);
                setError(null);
                setShowTechnical(false);
              }}
              disabled={!permit && !error}
            >
              Clear
            </button>
          </div>

          {error && <div className="alert bad">{error}</div>}
        </section>

        {/* Permit Summary */}
        <section className="card">
          <h2>Compliance Authorization</h2>
          {!permit && (
            <p className="muted">
              Request a permit to generate a time-bound Proof Bundle (5 minutes).
            </p>
          )}

          {permit && (
            <>
              <div className="summary">
                <div className="item">
                  <span className="check">✔</span> Issuer verified
                </div>
                <div className="item">
                  <span className="check">✔</span> Asset classification:{" "}
                  <b>{permit.summary.asset_classification}</b>
                </div>
                <div className="item">
                  <span className="check">✔</span> Custody attestation bound
                </div>
                <div className="item">
                  <span className="check">✔</span> Reserve backing attestation bound
                </div>
                <div className="item">
                  <span className="check">✔</span> Policy: <b>{permit.summary.policy_version}</b>
                </div>
              </div>

              <div className="row spaceTop">
                <button className="btn" onClick={() => setShowTechnical((v) => !v)}>
                  {showTechnical ? "Hide Technical Proof" : "View Technical Proof"}
                </button>

                <button className="btn" onClick={verifyPermit}>
                  Verify Permit
                </button>
              </div>

              {verifyResult && (
                <div
                  className={`alert ${
                    verifyResult.signature_valid && verifyResult.not_expired ? "warn" : "bad"
                  }`}
                >
                  Verification → signature_valid=
                  <b>{String(verifyResult.signature_valid)}</b> | not_expired=
                  <b>{String(verifyResult.not_expired)}</b>
                </div>
              )}

              {showTechnical && (
                <div className="codeBlock">
                  <div className="codeTitle">Bundle Hash (SHA-256)</div>
                  <pre>{permit.bundle_hash}</pre>

                  <div className="codeTitle">Proof Bundle (raw)</div>
                  <pre>{JSON.stringify(permit.bundle, null, 2)}</pre>

                  <div className="codeTitle">Signature</div>
                  <pre>{permit.signature}</pre>
                </div>
              )}

              {!permitActive && (
                <div className="alert warn">
                  Permit expired. Request a new permit to continue.
                </div>
              )}
            </>
          )}
        </section>

        {/* Trustline */}
        <section className="card">
          <h2>Trustline</h2>
          <p className="muted">
            Next step: create an RLUSD trustline with the Proof Bundle attached (XRPL integration).
          </p>
          <button className="btn primary" disabled={!permitActive}>
            Create RLUSD Trustline (coming next)
          </button>
        </section>

        {/* Transfer */}
        <section className="card">
          <h2>Transfer</h2>
          <p className="muted">
            Next step: send RLUSD with the Proof Bundle attached (XRPL integration).
          </p>

          <label className="label">Recipient</label>
          <input className="input" placeholder="r..." disabled={!permitActive} />

          <label className="label">Amount</label>
          <input className="input" placeholder="10" disabled={!permitActive} />

          <button className="btn primary" disabled={!permitActive}>
            Send RLUSD (coming next)
          </button>
        </section>
      </main>

      <footer className="footer">
        <span className="muted">
          MVP: permits are signed & time-bound. Hard enforcement via Hooks is a future phase.
        </span>
      </footer>
    </div>
  );
}
