import { useEffect, useMemo, useRef, useState } from "react";
import "./App.css";
import RequestPermitPanel, { type PermitResponse, type PermitConstraints } from "./RequestPermitPanel";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";
const FETCH_TIMEOUT_MS = 15_000;

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

type SettlementVerifyResponse = {
  settlement_verified: boolean;
  permit_valid: boolean;
  permit_expired: boolean;
  tx_hash: string;
  bundle_hash: string;
  network: string;
  checks: Record<string, boolean>;
  details: Record<string, string>;
  verified_at: number;
};

type XrplHealth = {
  xrpl_configured: boolean;
  reachable: boolean;
  network: string;
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

function xrplConfiguredLabel(health: XrplHealth | null): string {
  if (!health) return "Checking...";
  return health.xrpl_configured ? "Configured" : "Not Configured";
}

function xrplReachableLabel(health: XrplHealth | null): string {
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
  const [commitResult, setCommitResult] = useState<SettlementVerifyResponse | null>(null);
  const [commitError, setCommitError] = useState<string | null>(null);
  const [committing, setCommitting] = useState(false);
  const [xrplHealth, setXrplHealth] = useState<XrplHealth | null>(null);
  const [txHash, setTxHash] = useState("");
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
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    fetch(`${API_BASE}/v1/xrpl/health`, { signal: controller.signal })
      .then((r) => r.json())
      .then((d: XrplHealth) => setXrplHealth(d))
      .catch((err) => {
        console.error("Failed to fetch XRPL health:", err);
        setXrplHealth({ xrpl_configured: false, reachable: false, network: "" });
      })
      .finally(() => clearTimeout(timeout));
  }, []);

  const remaining = useMemo(() => {
    if (!permit) return 0;
    return Math.max(0, permit.expires_at - now);
  }, [permit, now]);

  const status = useMemo(() => {
    if (commitResult?.settlement_verified) return { label: "Verified", kind: "anchored" as const };
    if (commitResult && !commitResult.settlement_verified) return { label: "Settlement Failed", kind: "bad" as const };
    if (!permit) return { label: "No Permit", kind: "neutral" as const };
    if (remaining <= 0) return { label: "Expired", kind: "bad" as const };
    if (remaining < 60) return { label: "Expiring Soon", kind: "warn" as const };
    return { label: "Active", kind: "good" as const };
  }, [permit, remaining, commitResult]);

  const expiryPercent = useMemo(() => {
    if (!permit || remaining <= 0 || permit.expires_in_seconds <= 0) return 0;
    return Math.min(100, (remaining / permit.expires_in_seconds) * 100);
  }, [permit, remaining]);

  async function verifyPermit() {
    if (!permit) return;
    setVerifyError(null);
    setVerifyResult(null);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(`${API_BASE}/v1/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ bundle: permit.bundle, signature: permit.signature }),
        signal: controller.signal,
      });

      const data = await res.json();
      if (!res.ok) {
        setVerifyError(extractErrorMessage(data, "Failed to verify permit."));
        return;
      }
      if (
        !data ||
        typeof data !== "object" ||
        typeof (data as Record<string, unknown>).signature_valid !== "boolean" ||
        typeof (data as Record<string, unknown>).not_expired !== "boolean"
      ) {
        setVerifyError("Unexpected response from server.");
        return;
      }
      setVerifyResult(data as VerifyResponse);
    } catch (e: unknown) {
      if (e instanceof Error && e.name === "AbortError") {
        setVerifyError("Request timed out. Please try again.");
      } else {
        setVerifyError(e instanceof Error ? e.message : "Network error calling verify endpoint.");
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  async function verifySettlement() {
    if (!permit || !txHash.trim()) return;
    setCommitError(null);
    setCommitResult(null);
    setCommitting(true);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(`${API_BASE}/v1/settle/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tx_hash: txHash.trim(),
          bundle: permit.bundle,
          signature: permit.signature,
        }),
        signal: controller.signal,
      });

      const data = await res.json();
      if (!res.ok) {
        setCommitError(extractErrorMessage(data, "Failed to verify settlement."));
      } else if (
        !data ||
        typeof data !== "object" ||
        typeof (data as Record<string, unknown>).settlement_verified !== "boolean"
      ) {
        setCommitError("Unexpected response from server.");
      } else {
        setCommitResult(data as SettlementVerifyResponse);
      }
    } catch (e: unknown) {
      if (e instanceof Error && e.name === "AbortError") {
        setCommitError("Request timed out. Please try again.");
      } else {
        setCommitError(e instanceof Error ? e.message : "Network error calling settlement verify endpoint.");
      }
    } finally {
      clearTimeout(timeout);
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
        <span className="adapterBarLabel">XRPL Network</span>
        <span className={`badge ${xrplHealth === null ? "neutral" : xrplHealth.xrpl_configured ? "good" : "bad"}`}>
          <span className="badgeDot" />
          {xrplConfiguredLabel(xrplHealth)}
        </span>
        <span className={`badge ${xrplHealth === null ? "neutral" : xrplHealth.reachable ? "good" : "bad"}`}>
          <span className="badgeDot" />
          {xrplReachableLabel(xrplHealth)}
        </span>
        {xrplHealth?.network && (
          <span className="badge neutral">
            <span className="badgeDot" />
            {xrplHealth.network}
          </span>
        )}
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
            setTxHash("");
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
                  <div className="codeTitleRow">
                    <div className="codeTitle">Proof Artifact</div>
                    <button
                      className="copyBtn"
                      onClick={() => copyToClipboard(JSON.stringify(permit.proof_artifact, null, 2), "proof_artifact")}
                      title="Copy proof artifact"
                    >
                      {copied === "proof_artifact" ? "✔ Copied" : "Copy"}
                    </button>
                  </div>
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
                  {verifyResult.action && (
                    <div className="verifyRow">
                      <span className="check">✔</span>
                      <span className="summaryLabel">Action</span>
                      <span className="summaryValue">{verifyResult.action}</span>
                    </div>
                  )}
                  {verifyResult.policy_version && (
                    <div className="verifyRow">
                      <span className="check">✔</span>
                      <span className="summaryLabel">Policy version</span>
                      <span className="summaryValue">{verifyResult.policy_version}</span>
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

        {/* Panel 5: Settlement Verification */}
        <section className="card">
          <h2><PanelNumber n={5} />Settlement Verification</h2>
          <p className="muted">
            After executing a transaction on XRPL, paste the transaction hash to verify it satisfies the permit constraints.
          </p>

          <label className="label">XRPL Transaction Hash</label>
          <input
            className="input"
            value={txHash}
            onChange={(e) => setTxHash(e.target.value)}
            placeholder="Enter XRPL tx hash..."
            spellCheck={false}
            disabled={!permit}
          />

          <div className="row">
            <button
              className="btn primary"
              onClick={verifySettlement}
              disabled={!permit || !txHash.trim() || committing}
            >
              {committing ? "Verifying…" : "Verify Settlement"}
            </button>
          </div>

          {commitResult && (
            <div className="commitResult">
              <div className="commitResultHeader">
                <span className={`badge ${commitResult.settlement_verified ? "anchored" : "bad"}`}>
                  <span className="badgeDot" />
                  {commitResult.settlement_verified ? "✔ Settlement Verified" : "✘ Settlement Failed"}
                </span>
              </div>

              <div className="commitRows">
                <div className="commitRow">
                  <span className="commitLabel">Verified</span>
                  <span className={`commitValue${commitResult.settlement_verified ? " textGood" : " textBad"}`}>
                    {String(commitResult.settlement_verified)}
                  </span>
                </div>

                <div className="commitRow">
                  <span className="commitLabel">TX Hash</span>
                  <span className="commitValue commitValueMono" style={{ wordBreak: "break-all" }}>
                    {commitResult.tx_hash}
                  </span>
                </div>

                <div className="commitRow">
                  <span className="commitLabel">Network</span>
                  <span className="commitValue">{commitResult.network}</span>
                </div>

                <div className="commitRow">
                  <span className="commitLabel">Permit Valid</span>
                  <span className={`commitValue${commitResult.permit_valid ? " textGood" : " textBad"}`}>
                    {String(commitResult.permit_valid)}
                  </span>
                </div>

                {commitResult.permit_expired && (
                  <div className="commitRow">
                    <span className="commitLabel">Permit Expired</span>
                    <span className="commitValue textBad">true</span>
                  </div>
                )}

                <div className="commitRow">
                  <span className="commitLabel">Verified At</span>
                  <span className="commitValue">
                    {new Date(commitResult.verified_at * 1000).toISOString()}
                  </span>
                </div>

                {/* Individual checks */}
                {Object.entries(commitResult.checks).length > 0 && (
                  <div className="commitMetaBlock">
                    <div className="codeTitle">Compliance Checks</div>
                    {Object.entries(commitResult.checks).map(([key, passed]) => (
                      <div key={key} className="verifyRow">
                        <span className={passed ? "check" : "check checkFail"}>
                          {passed ? "✔" : "✘"}
                        </span>
                        <span className="summaryLabel">{key.replace(/_/g, " ")}</span>
                        <span className={`summaryValue${passed ? " textGood" : " textBad"}`}>
                          {passed ? "pass" : commitResult.details[key] ?? "fail"}
                        </span>
                      </div>
                    ))}
                  </div>
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
