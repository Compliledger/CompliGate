import { useEffect, useMemo, useState } from "react";

import "./App.css";
import ApiSettings from "./ApiSettings";
import EnvWarnings from "./EnvWarnings";
import PermitSummaryPanel, { type PermitStatus } from "./components/PermitSummaryPanel";
import PermitVerificationPanel from "./components/PermitVerificationPanel";
import RequestPermitPanel from "./components/RequestPermitPanel";
import SettlementVerificationPanel from "./components/SettlementVerificationPanel";
import TechnicalProofPanel from "./components/TechnicalProofPanel";
import TransactionLookupPanel from "./components/TransactionLookupPanel";
import TrustlineCheckPanel from "./components/TrustlineCheckPanel";
import TransactionLookupPanel from "./components/TransactionLookupPanel";
import StatusMessage from "./components/StatusMessage";
import { apiGet, apiPost, describeError } from "./lib/api";
import { useCopyToClipboard } from "./lib/useCopyToClipboard";
import type {
  PermitResponse,
  SettlementVerifyResponse,
  TrustlineCheckResponse,
  VerifyResponse,
  XRPLHealthResponse,
  XRPLPaymentResponse,
} from "./types/api";

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

function PanelNumber({ n }: { n: number }) {
  return <span className="panelNumber">{n}</span>;
}

type BadgeTone = "neutral" | "good" | "warn" | "bad";

type HealthBadge = {
  label: string;
  value: string;
  tone: BadgeTone;
};

function buildXrplHealthBadges(
  health: XRPLHealthResponse | null,
  loading: boolean,
  errored: boolean,
): HealthBadge[] {
  if (loading) {
    return [
      { label: "Configured", value: "Loading…", tone: "neutral" },
      { label: "Reachable", value: "Loading…", tone: "neutral" },
      { label: "Network", value: "Loading…", tone: "neutral" },
      { label: "RLUSD", value: "Loading…", tone: "neutral" },
    ];
  }

  if (!health || errored) {
    return [
      { label: "Configured", value: "Unavailable", tone: "bad" },
      { label: "Reachable", value: "Unavailable", tone: "bad" },
      { label: "Network", value: "Unavailable", tone: "bad" },
      { label: "RLUSD", value: "Unavailable", tone: "bad" },
    ];
  }

  const badges: HealthBadge[] = [
    {
      label: "Configured",
      value: health.configured ? "Yes" : "No",
      tone: health.configured ? "good" : "bad",
    },
    {
      label: "Reachable",
      value: health.reachable ? "Yes" : "No",
      // Reachability only matters once configured; surface as warn when not
      // configured so it does not look like a hard failure.
      tone: health.reachable ? "good" : health.configured ? "bad" : "warn",
    },
    {
      label: "Network",
      value: health.network || "Unknown",
      tone: health.network ? "neutral" : "warn",
    },
    {
      label: "RLUSD",
      value: health.rlusd_configured ? "Configured" : "Not configured",
      tone: health.rlusd_configured ? "good" : "warn",
    },
  ];

  // Demo wallet badge is only rendered if the backend reports it as still
  // configured — surface it as a warning so operators notice it's present.
  if (health.demo_wallet_configured) {
    badges.push({
      label: "Demo wallet",
      value: "Configured",
      tone: "warn",
    });
  }

  if (health.signing_enabled !== undefined) {
    badges.push({
      label: "Signing",
      value: health.signing_enabled ? "Enabled" : "Disabled",
      tone: health.signing_enabled ? "good" : "warn",
    });
  }

  if (health.signing_mode !== undefined) {
    const mode = health.signing_mode ? health.signing_mode : "unknown";
    badges.push({
      label: "Signing mode",
      value: mode,
      tone: mode === "disabled" || mode === "unknown" ? "warn" : "neutral",
    });
  }

  if (health.signer_configured !== undefined) {
    badges.push({
      label: "Signer",
      value: health.signer_configured ? "Configured" : "Not configured",
      tone: health.signer_configured ? "good" : "warn",
    });
  }

  return badges;
}

import XRPLHealthPanel from "./components/XRPLHealthPanel";
import XRPLPaymentPanel from "./components/XRPLPaymentPanel";
import { formatSeconds } from "./lib/format";
import type { PermitResponse, SettlementVerifyResponse } from "./types/api";

/**
 * App
 *
 * Page-level orchestrator. Owns only the state that is shared across
 * panels (the active permit, the settled XRPL transaction hash and its
 * verification result, plus a one-second timer used for the expiry
 * countdown), wires data flow between panels, and renders the high
 * level layout (header, health bar, settings, panel grid, footer).
 *
 * All domain logic, fetching and presentation now lives in the
 * dedicated panel components under `./components/`.
 */
export default function App() {
  const [permit, setPermit] = useState<PermitResponse | null>(null);
  const [now, setNow] = useState<number>(() => Math.floor(Date.now() / 1000));
  const [settledTxHash, setSettledTxHash] = useState("");
  const [settlementResult, setSettlementResult] = useState<SettlementVerifyResponse | null>(null);
  const [settlementError, setSettlementError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [trustlineResult, setTrustlineResult] = useState<TrustlineCheckResponse | null>(null);
  const [xrplPaymentResult, setXrplPaymentResult] = useState<XRPLPaymentResponse | null>(null);

  useEffect(() => {
    const t = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(t);
  }, []);

  const remaining = useMemo(() => {
    if (!permit) return 0;
    return Math.max(0, permit.expires_at - now);
  }, [permit, now]);

  const settlementPassed = useMemo(() => {
    if (!settlementResult) return false;
    const d = settlementResult.decision_result.toLowerCase();
    return d === "permit" || d === "allow" || d === "approved";
  }, [settlementResult]);

  const status = useMemo<PermitStatus>(() => {
    if (settlementResult && settlementPassed) return { label: "Verified", kind: "anchored" };
    if (settlementResult && !settlementPassed) return { label: "Settlement Failed", kind: "bad" };
    if (!permit) return { label: "No Permit", kind: "neutral" };
    if (remaining <= 0) return { label: "Expired", kind: "bad" };
    if (remaining < 60) return { label: "Expiring Soon", kind: "warn" };
    return { label: "Active", kind: "good" };
  }, [permit, remaining, settlementResult, settlementPassed]);

  function handlePermit(p: PermitResponse) {
    setPermit(p);
    setSettledTxHash("");
    setSettlementResult(null);
  }

  function handleClearPermit() {
    setPermit(null);
    setSettledTxHash("");
    setSettlementResult(null);
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
          {permit && remaining > 0 && !settlementResult && (
            <span className="pillRight">{formatSeconds(remaining)}</span>
          )}
        </div>
      </header>

      <XRPLHealthPanel />

      <EnvWarnings />

      <ApiSettings />

      <main className="grid">
        {/* Panel 1: Request Permit */}
        <RequestPermitPanel
          onPermit={(p) => {
            setPermit(p);
            setVerifyResult(null);
            setVerifyError(null);
            setSettledTxHash("");
            setSettlementResult(null);
            setSettlementError(null);
          }}
          onClear={() => {
            setPermit(null);
            setVerifyResult(null);
            setVerifyError(null);
            setSettlementResult(null);
            setSettlementError(null);
            setSettledTxHash("");
          }}
        />

        {/* Supplemental: Permit Constraints Snapshot */}
        <section className="card" style={{ order: 7 }}>
          <div className="summaryHeader">
            <h2>Permit Constraints Snapshot</h2>
            <span className={`badge ${status.kind}`}>
              <span className="badgeDot" />
              {status.label}
            </span>
          </div>

          {!permit ? (
            <StatusMessage variant="empty" title="No permit yet">
              Request a permit to view the constraints.
            </StatusMessage>
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
                {permit.bundle.asset.regulatory_treatment && (
                  <div className="summaryRow">
                    <span className="check">✔</span>
                    <span className="summaryLabel">Regulatory treatment</span>
                    <span className="summaryValue">{permit.bundle.asset.regulatory_treatment}</span>
                  </div>
                )}
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

              <div className="regulatoryControlsHeader">XRPL / RLUSD Regulatory Controls</div>
              <div className="summary">
                {permit.bundle.constraints.reserve_backed !== undefined && (
                  <div className="summaryRow">
                    <span className={checkClass(permit.bundle.constraints.reserve_backed)}>
                      {checkSymbol(permit.bundle.constraints.reserve_backed)}
                    </span>
                    <span className="summaryLabel">Reserve backed</span>
                    <span className="summaryValue">
                      {permit.bundle.constraints.reserve_backed ? "Yes" : "No"}
                    </span>
                  </div>
                )}
                {permit.bundle.constraints.liquidity_verified !== undefined && (
                  <div className="summaryRow">
                    <span className={checkClass(permit.bundle.constraints.liquidity_verified)}>
                      {checkSymbol(permit.bundle.constraints.liquidity_verified)}
                    </span>
                    <span className="summaryLabel">Liquidity verified</span>
                    <span className="summaryValue">
                      {permit.bundle.constraints.liquidity_verified ? "Yes" : "No"}
                    </span>
                  </div>
                )}
                {permit.bundle.constraints.kyc_verified !== undefined && (
                  <div className="summaryRow">
                    <span className={checkClass(permit.bundle.constraints.kyc_verified)}>
                      {checkSymbol(permit.bundle.constraints.kyc_verified)}
                    </span>
                    <span className="summaryLabel">KYC verified</span>
                    <span className="summaryValue">
                      {permit.bundle.constraints.kyc_verified ? "Yes" : "No"}
                    </span>
                  </div>
                )}
                {permit.bundle.constraints.sanctions_check !== undefined && (
                  <div className="summaryRow">
                    <span className={checkClass(permit.bundle.constraints.sanctions_check === "passed")}>
                      {checkSymbol(permit.bundle.constraints.sanctions_check === "passed")}
                    </span>
                    <span className="summaryLabel">Sanctions check</span>
                    <span className="summaryValue">{permit.bundle.constraints.sanctions_check}</span>
                  </div>
                )}
                {permit.bundle.constraints.jurisdiction && (
                  <div className="summaryRow">
                    <span className="check">✔</span>
                    <span className="summaryLabel">Jurisdiction</span>
                    <span className="summaryValue">{permit.bundle.constraints.jurisdiction}</span>
                  </div>
                )}
                {permit.bundle.constraints.max_amount !== undefined && (
                  <div className="summaryRow">
                    <span className="check">✔</span>
                    <span className="summaryLabel">Max amount</span>
                    <span className="summaryValue">{permit.bundle.constraints.max_amount}</span>
                  </div>
                )}
                {permit.bundle.constraints.freeze_possible !== undefined && (
                  <div className="summaryRow">
                    <span className={checkClass(permit.bundle.constraints.freeze_possible)}>
                      {checkSymbol(permit.bundle.constraints.freeze_possible)}
                    </span>
                    <span className="summaryLabel">Freeze possible</span>
                    <span className="summaryValue">
                      {permit.bundle.constraints.freeze_possible ? "Yes" : "No"}
                    </span>
                  </div>
                )}
                {permit.bundle.constraints.clawback_possible !== undefined && (
                  <div className="summaryRow">
                    <span className={checkClass(permit.bundle.constraints.clawback_possible)}>
                      {checkSymbol(permit.bundle.constraints.clawback_possible)}
                    </span>
                    <span className="summaryLabel">Clawback possible</span>
                    <span className="summaryValue">
                      {permit.bundle.constraints.clawback_possible ? "Yes" : "No"}
                    </span>
                  </div>
                )}
                {permit.bundle.constraints.trustline_required !== undefined && (
                  <div className="summaryRow">
                    <span className={checkClass(permit.bundle.constraints.trustline_required)}>
                      {checkSymbol(permit.bundle.constraints.trustline_required)}
                    </span>
                    <span className="summaryLabel">Trustline required</span>
                    <span className="summaryValue">
                      {permit.bundle.constraints.trustline_required ? "Yes" : "No"}
                    </span>
                  </div>
                )}
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

        {/* Panel 3: Submit XRPL Payment */}
        <XRPLPaymentPanel
          permit={permit}
          panelNumber={3}
          order={3}
          result={xrplPaymentResult}
          onResult={setXrplPaymentResult}
        />

        {/* Panel 4: Provide Settled XRPL Transaction */}
        <section className="card" style={{ order: 4 }}>
          <h2><PanelNumber n={4} />Provide Settled XRPL Transaction Hash</h2>
          <p className="muted">
            Settle from your own XRPL wallet, then paste the settled transaction hash for verification.
          </p>

          <label className="label">Settled Transaction Hash</label>
          <input
            className="input"
            value={settledTxHash}
            onChange={(e) => setSettledTxHash(e.target.value)}
            placeholder="Enter XRPL transaction hash..."
            spellCheck={false}
          />

          <div className="row">
            <button
              className="btn primary"
              onClick={() => verifySettlement()}
              disabled={!canVerifySettlement || verifying}
            >
              {verifying ? "Verifying…" : "Verify Settlement"}
            </button>
            <button
              className="btn"
              onClick={() => {
                setSettledTxHash("");
                setSettlementResult(null);
                setSettlementError(null);
              }}
            >
              Clear
            </button>
          </div>

          {settledTxHash.trim() ? (
            <div className="verifyRows">
              <div className="verifyRow">
                <span className="check">✔</span>
                <span className="summaryLabel">TX Hash</span>
                <span className="summaryValue commitValueMono breakAll">{settledTxHash.trim()}</span>
                <button
                  className="copyBtn"
                  onClick={() => copyToClipboard(settledTxHash.trim(), "provided_tx_hash")}
                  title="Copy tx_hash"
                >
                  {copied === "provided_tx_hash" ? "✔ Copied" : "Copy"}
                </button>
              </div>
            </div>
          ) : (
            <StatusMessage variant="empty" title="No transaction hash provided">
              Paste a settled XRPL transaction hash above to bind it to the active permit.
            </StatusMessage>
          )}
        </section>

        {/* Panel 5: Verify Settlement */}
        <section className="card" style={{ order: 5 }}>
          <h2><PanelNumber n={5} />Verify Settlement</h2>
          <p className="muted">
            Verification of a settled XRPL transaction against permit hash and constraints.
          </p>

          <div className="row">
            <button
              className="btn primary"
              onClick={verifySettlement}
              disabled={!canVerifySettlement || verifying}
            >
              {verifying ? "Verifying…" : "Verify Settlement"}
            </button>
          </div>
          {!canVerifySettlement && (
            <StatusMessage variant="warning" title="Verification prerequisites missing">
              Requires both a permit bundle hash and a settled XRPL transaction hash.
            </StatusMessage>
          )}
          {canVerifySettlement && !verifying && !settlementResult && !settlementError && (
            <StatusMessage variant="empty" title="No settlement verified yet">
              Click <strong>Verify Settlement</strong> to check the transaction against the permit.
            </StatusMessage>
          )}
          {verifying && (
            <StatusMessage variant="loading" title="Verifying settlement…">
              Comparing the on-ledger transaction to the permit constraints.
            </StatusMessage>
          )}

          {settlementResult && (() => {
            const artifact = settlementResult.proof_artifact;
            const anchorTxHash = artifact.anchor_metadata?.tx_hash;
            const txHash =
              (typeof settlementResult.tx_hash === "string" && settlementResult.tx_hash) ||
              (typeof anchorTxHash === "string" && anchorTxHash) ||
              settledTxHash.trim();
            const bundleHash =
              (typeof settlementResult.bundle_hash === "string" && settlementResult.bundle_hash) ||
              artifact.bundle_hash ||
              permit?.bundle_hash;
            const artifactTimestamp =
              typeof artifact.timestamp === "number"
                ? new Date(artifact.timestamp * 1000).toISOString()
                : null;
            return (
              <div className="verifyResult">
                <div className={`verifyHeader ${settlementPassed ? "good" : "bad"}`}>
                  <span className={`verifyIcon ${settlementPassed ? "good" : "bad"}`}>
                    {settlementPassed ? "✔" : "✘"}
                  </span>
                  {settlementPassed ? "PASS" : "FAIL"} — {settlementResult.decision_result}
                </div>

                <div className="verifyRows">
                  <div className="verifyRow">
                    <span className={checkClass(settlementPassed)}>
                      {checkSymbol(settlementPassed)}
                    </span>
                    <span className="summaryLabel">Decision Result</span>
                    <span className={`summaryValue${settlementPassed ? " textGood" : " textBad"}`}>
                      {settlementResult.decision_result}
                    </span>
                  </div>
                  {artifact.module && (
                    <div className="verifyRow">
                      <span className="check">✔</span>
                      <span className="summaryLabel">Module</span>
                      <span className="summaryValue">{artifact.module}</span>
                    </div>
                  )}
                  {artifact.entity_id && (
                    <div className="verifyRow">
                      <span className="check">✔</span>
                      <span className="summaryLabel">Entity ID</span>
                      <span className="summaryValue commitValueMono breakAll">{artifact.entity_id}</span>
                    </div>
                  )}
                  {artifact.rule_version_used && (
                    <div className="verifyRow">
                      <span className="check">✔</span>
                      <span className="summaryLabel">Rule Version</span>
                      <span className="summaryValue">{artifact.rule_version_used}</span>
                    </div>
                  )}
                  {artifactTimestamp && (
                    <div className="verifyRow">
                      <span className="check">✔</span>
                      <span className="summaryLabel">Timestamp</span>
                      <span className="summaryValue">{artifactTimestamp}</span>
                    </div>
                  )}
                  {txHash && (
                    <div className="verifyRow">
                      <span className="check">✔</span>
                      <span className="summaryLabel">TX Hash</span>
                      <span className="summaryValue commitValueMono breakAll">{txHash}</span>
                      <button
                        className="copyBtn"
                        onClick={() => copyToClipboard(txHash, "stl_tx_hash")}
                        title="Copy tx_hash"
                      >
                        {copied === "stl_tx_hash" ? "✔ Copied" : "Copy"}
                      </button>
                    </div>
                  )}
                  {bundleHash && (
                    <div className="verifyRow">
                      <span className="check">✔</span>
                      <span className="summaryLabel">Bundle Hash</span>
                      <span className="summaryValue commitValueMono breakAll">{bundleHash}</span>
                      <button
                        className="copyBtn"
                        onClick={() => copyToClipboard(bundleHash, "stl_bundle_hash")}
                        title="Copy bundle_hash"
                      >
                        {copied === "stl_bundle_hash" ? "✔ Copied" : "Copy"}
                      </button>
                    </div>
                  )}
                </div>

                <div className="reasonCodes">
                  <div className="reasonCodesTitle">Reason Codes</div>
                  <div className="reasonCodesList">
                    {settlementResult.reason_codes.length > 0 ? settlementResult.reason_codes.map((rc) => (
                      <span key={rc} className="reasonCode">{rc}</span>
                    )) : (
                      <span className="reasonCode">none</span>
                    )}
                  </div>
                </div>

                <div className="proofArtifactBlock">
                  <details className="proofArtifactDetails">
                    <summary className="proofArtifactSummary">
                      Proof Artifact
                      <button
                        className="copyBtn"
                        onClick={(e) => {
                          e.preventDefault();
                          copyToClipboard(JSON.stringify(artifact, null, 2), "stl_proof_artifact");
                        }}
                        title="Copy proof artifact JSON"
                      >
                        {copied === "stl_proof_artifact" ? "✔ Copied" : "Copy"}
                      </button>
                    </summary>
                    <pre className="proofArtifactPre">{JSON.stringify(artifact, null, 2)}</pre>
                  </details>
                </div>
              </div>
            );
          })()}

          {settlementError && (
            <StatusMessage variant="error" title="Settlement verification failed">
              {settlementError}
            </StatusMessage>
          )}
        </section>

        {/* Panel 6: View Proof Artifact */}
        <section className="card spanFull" style={{ order: 6 }}>
          <h2><PanelNumber n={6} />View Proof Artifact</h2>
          {!permit ? (
            <StatusMessage variant="empty" title="No proof artifact yet">
              Proof and signature artifact details will appear here after a permit is issued.
            </StatusMessage>
          ) : (
            <>
              <div className="row" style={{ marginTop: 0 }}>
                <button
                  className="btn primary"
                  onClick={verifyPermit}
                  disabled={!permit || verifyingPermit}
                >
                  {verifyingPermit ? "Verifying…" : "Verify Permit Signature"}
                </button>
              </div>

              {verifyError && (
                <StatusMessage variant="error" title="Permit verification failed">
                  {verifyError}
                </StatusMessage>
              )}
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

                <div className="codeTitleRow">
                  <div className="codeTitle">Regulatory Controls (JSON)</div>
                  <button
                    className="copyBtn"
                    onClick={() => copyToClipboard(regulatoryControlsJson, "reg_controls")}
                    title="Copy regulatory controls"
                  >
                    {copied === "reg_controls" ? "✔ Copied" : "Copy"}
                  </button>
                </div>
                <pre>{regulatoryControlsJson}</pre>

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
            </>
          )}
        </section>
        <RequestPermitPanel onPermit={handlePermit} onClear={handleClearPermit} />

        {/* Panel 2: Check Trustline */}
        <section className="card" style={{ order: 2 }}>
          <TrustlineCheckPanel
            panelNumber={2}
            result={trustlineResult}
            onResult={setTrustlineResult}
          />
        </section>

        {/* Supplemental: XRPL Transaction Lookup */}
        <TransactionLookupPanel onUseHash={setSettledTxHash} />
        {/* Panel 3: Submit XRPL Payment */}
        <XRPLPaymentPanel permit={permit} panelNumber={3} order={3} />

        {/* Panels 4 + 5: Settlement Verification (settled tx hash + verify) */}
        <SettlementVerificationPanel
          permit={permit}
          settledTxHash={settledTxHash}
          onSettledTxHashChange={setSettledTxHash}
          settlementResult={settlementResult}
          onSettlementResult={setSettlementResult}
          inputOrder={4}
          verifyOrder={5}
          inputPanelNumber={4}
          verifyPanelNumber={5}
        />

        {/* Panel 6: Permit Verification */}
        <PermitVerificationPanel permit={permit} panelNumber={6} order={6} />

        {/* Panel 7: Permit Constraints Snapshot */}
        <PermitSummaryPanel permit={permit} status={status} remaining={remaining} order={7} />

        {/* Panel 8: Transaction Lookup (supplemental) */}
        <TransactionLookupPanel onUseHash={setSettledTxHash} order={8} />

        {/* Panel 9: Technical Proof Artifact */}
        <TechnicalProofPanel permit={permit} order={9} />
      </main>

      <footer className="footer">
        <span className="muted">
          MVP · Authorization and constraints are signed and time-bound · CompliGate verifies settled XRPL outcomes
        </span>
      </footer>
    </div>
  );
}
