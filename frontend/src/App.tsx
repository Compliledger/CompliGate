import { useEffect, useMemo, useRef, useState } from "react";
import "./App.css";
import RequestPermitPanel, { type PermitBundle, type PermitValidity } from "./RequestPermitPanel";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

type PermitConstraints = {
  max_amount: number;
  allowed_counterparty?: string | null;
};

type VerifyResponse = {
  signature_valid: boolean;
  not_expired: boolean;
  subject?: string;
  policy_version?: string;
  action?: string;
  bundle_hash?: string;
  constraints?: PermitConstraints;
  decision_result?: string;
  reason_codes?: string[];
};

type AnchorMetadata = {
  network?: string;
  tx_id?: string;
  confirmed_round?: number;
  app_id?: number;
  method?: string;
  contract_version?: string;
  anchored_at?: number;
};

type CommitResponse = {
  committed: boolean;
  algorand_tx_id?: string;
  bundle_hash?: string;
  anchor_metadata?: AnchorMetadata;
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
  const [permit, setPermit] = useState<PermitResponse | null>(null);
  const [now, setNow] = useState<number>(() => Math.floor(Date.now() / 1000));
  const [verifyResult, setVerifyResult] = useState<VerifyResponse | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [commitResult, setCommitResult] = useState<CommitResponse | null>(null);
  const [commitError, setCommitError] = useState<string | null>(null);
  const [committing, setCommitting] = useState(false);
  const [adapterHealth, setAdapterHealth] = useState<AdapterHealth | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
    };
  }, []);

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

  const expiryPercent = useMemo(() => {
    if (!permit || remaining <= 0 || permit.expires_in_seconds <= 0) return 0;
    return Math.min(100, (remaining / permit.expires_in_seconds) * 100);
  }, [permit, remaining]);

  async function verifyPermit() {
    if (!permit) return;
    setVerifyError(null);
    setVerifyResult(null);

    try {
      const res = await fetch(`${API_BASE}/v1/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ bundle: permit.bundle, signature: permit.signature }),
      });

      const data = await res.json();
      if (!res.ok) {
        setVerifyError(extractErrorMessage(data, "Failed to verify permit."));
        return;
      }
      setVerifyResult(data);
    } catch (e: unknown) {
      setVerifyError(e instanceof Error ? e.message : "Network error calling verify endpoint.");
    }
  }

  async function commitToAlgorand() {
    if (!permit) return;
    setCommitError(null);
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
        setCommitError(extractErrorMessage(data, "Failed to commit to Algorand."));
      } else {
        setCommitResult(data);
      }
    } catch (e: unknown) {
      setCommitError(e instanceof Error ? e.message : "Network error calling commit endpoint.");
    } finally {
      setCommitting(false);
    }
  }

  async function copyToClipboard(text: string, key: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
      copyTimerRef.current = setTimeout(
        () => setCopied((prev) => (prev === key ? null : prev)),
        2000
      );
    } catch {
      // silent fail — clipboard API unavailable
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
        <RequestPermitPanel
          onPermit={(p) => {
            setPermit(p);
            setVerifyResult(null);
            setVerifyError(null);
            setCommitResult(null);
            setCommitError(null);
          }}
          onClear={() => {
            setPermit(null);
            setVerifyResult(null);
            setVerifyError(null);
            setCommitResult(null);
            setCommitError(null);
          }}
        />

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
            <>
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

        {/* Panel 3: Technical Proof */}
        <section className="card spanFull">
          <h2><PanelNumber n={3} />Technical Proof</h2>
          {!permit ? (
            <p className="muted">
              Proof bundle details will appear here after a permit is issued.
            </p>
          ) : (
            <div className="codeBlock">
              <div className="codeTitleRow">
                <div className="codeTitle">Bundle Hash (SHA-256)</div>
                <button
                  className="copyBtn"
                  onClick={() => copyToClipboard(permit.bundle_hash, "bundle_hash")}
                  title="Copy bundle hash"
                >
                  {copied === "bundle_hash" ? "✔ Copied" : "Copy"}
                </button>
              </div>
              <pre>{permit.bundle_hash}</pre>

              <div className="codeTitle">Proof Bundle (raw JSON)</div>
              <pre>{JSON.stringify(permit.bundle, null, 2)}</pre>

              <div className="codeTitleRow">
                <div className="codeTitle">Signature</div>
                <button
                  className="copyBtn"
                  onClick={() => copyToClipboard(permit.signature, "signature")}
                  title="Copy signature"
                >
                  {copied === "signature" ? "✔ Copied" : "Copy"}
                </button>
              </div>
              <pre>{permit.signature}</pre>

              {permit.proof_artifact && (
                <>
                  <div className="codeTitle">Proof Artifact</div>
                  <pre>{JSON.stringify(permit.proof_artifact, null, 2)}</pre>
                </>
              )}
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

          {verifyError && <div className="alert bad">{verifyError}</div>}
          {verifyResult && (() => {
            const passed = verifyResult.signature_valid && verifyResult.not_expired;
            const decisionResult =
              verifyResult.decision_result ?? permit?.proof_artifact?.decision_result;
            const reasonCodes =
              verifyResult.reason_codes ?? permit?.proof_artifact?.reason_codes;
            return (
              <div className="verifyResult">
                <div className={`verifyHeader ${passed ? "good" : "bad"}`}>
                  <span className={`verifyIcon ${passed ? "good" : "bad"}`}>
                    {passed ? "✔" : "✘"}
                  </span>
                  {passed ? "PASS" : "FAIL"}
                </div>
                <div className="verifyRows">
                  <div className="verifyRow">
                    <span className={checkClass(verifyResult.signature_valid)}>
                      {checkSymbol(verifyResult.signature_valid)}
                    </span>
                    <span className="summaryLabel">Signature valid</span>
                    <span className="summaryValue">{String(verifyResult.signature_valid)}</span>
                  </div>
                  <div className="verifyRow">
                    <span className={checkClass(verifyResult.not_expired)}>
                      {checkSymbol(verifyResult.not_expired)}
                    </span>
                    <span className="summaryLabel">Not expired</span>
                    <span className="summaryValue">{String(verifyResult.not_expired)}</span>
                  </div>
                  {decisionResult && (
                    <div className="verifyRow">
                      <span className={checkClass(decisionResult === "PERMIT")}>
                        {checkSymbol(decisionResult === "PERMIT")}
                      </span>
                      <span className="summaryLabel">Decision result</span>
                      <span
                        className={`summaryValue${
                          decisionResult === "PERMIT" ? " textGood" : " textBad"
                        }`}
                      >
                        {decisionResult}
                      </span>
                    </div>
                  )}
                  {verifyResult.bundle_hash && (
                    <div className="verifyRow">
                      <span className="check">✔</span>
                      <span className="summaryLabel">Bundle hash</span>
                      <span className="summaryValue breakAll">{verifyResult.bundle_hash}</span>
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
            <div className="commitResult">
              <div className="commitResultHeader">
                <span className="badge anchored">
                  <span className="badgeDot" />
                  ⚓ Anchored
                </span>
              </div>

              <div className="commitRows">
                <div className="commitRow">
                  <span className="commitLabel">Committed</span>
                  <span className={`commitValue${commitResult.committed ? " textGood" : " textBad"}`}>
                    {String(commitResult.committed)}
                  </span>
                </div>

                {(commitResult.anchor_metadata?.tx_id ?? commitResult.algorand_tx_id) && (
                  <div className="commitRow">
                    <span className="commitLabel">TX ID</span>
                    <span className="commitValue commitValueMono" style={{ wordBreak: "break-all" }}>
                      {commitResult.anchor_metadata?.tx_id ?? commitResult.algorand_tx_id}
                    </span>
                  </div>
                )}

                {commitResult.anchor_metadata && (
                  <>
                    {commitResult.anchor_metadata.network && (
                      <div className="commitRow">
                        <span className="commitLabel">Network</span>
                        <span className="commitValue">{commitResult.anchor_metadata.network}</span>
                      </div>
                    )}
                    {commitResult.anchor_metadata.confirmed_round != null && (
                      <div className="commitRow">
                        <span className="commitLabel">Confirmed Round</span>
                        <span className="commitValue">{commitResult.anchor_metadata.confirmed_round}</span>
                      </div>
                    )}
                    {commitResult.anchor_metadata.app_id != null && (
                      <div className="commitRow">
                        <span className="commitLabel">App ID</span>
                        <span className="commitValue">{commitResult.anchor_metadata.app_id}</span>
                      </div>
                    )}
                    {commitResult.anchor_metadata.anchored_at != null && (
                      <div className="commitRow">
                        <span className="commitLabel">Anchored At</span>
                        <span className="commitValue">
                          {new Date(commitResult.anchor_metadata.anchored_at * 1000).toISOString()}
                        </span>
                      </div>
                    )}

                    <div className="commitMetaBlock">
                      <div className="codeTitle">Anchor Metadata</div>
                      <pre>{JSON.stringify(commitResult.anchor_metadata, null, 2)}</pre>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}

          {commitError && <div className="alert bad">{commitError}</div>}
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
