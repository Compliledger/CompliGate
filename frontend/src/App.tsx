import { useEffect, useMemo, useRef, useState } from "react";
import "./App.css";
import RequestPermitPanel from "./RequestPermitPanel";
import XRPLPaymentPanel from "./components/XRPLPaymentPanel";
import ApiSettings from "./ApiSettings";
import EnvWarnings from "./EnvWarnings";
import TrustlineCheckPanel from "./components/TrustlineCheckPanel";
import StatusMessage from "./components/StatusMessage";
import { apiGet, apiPost, describeError } from "./lib/api";
import type {
  PermitResponse,
  SettlementVerifyResponse,
  VerifyResponse,
  XRPLHealthResponse,
} from "./types/api";

type TxLookupAmount = {
  currency: string;
  value: string;
  issuer: string;
};

type TxLookupResponse = {
  tx_hash: string;
  validated: boolean;
  transaction_type: string;
  account: string;
  destination: string;
  amount: TxLookupAmount;
  engine_result: string;
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

export default function App() {
  const [permit, setPermit] = useState<PermitResponse | null>(null);
  const [now, setNow] = useState<number>(() => Math.floor(Date.now() / 1000));
  const [verifyResult, setVerifyResult] = useState<VerifyResponse | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [verifyingPermit, setVerifyingPermit] = useState(false);
  const [xrplHealth, setXrplHealth] = useState<XRPLHealthResponse | null>(null);
  const [xrplHealthLoading, setXrplHealthLoading] = useState(true);
  const [xrplHealthError, setXrplHealthError] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const [settledTxHash, setSettledTxHash] = useState("");
  const [settlementResult, setSettlementResult] = useState<SettlementVerifyResponse | null>(null);
  const [settlementError, setSettlementError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [txLookupHash, setTxLookupHash] = useState("");
  const [txLookupResult, setTxLookupResult] = useState<TxLookupResponse | null>(null);
  const [txLookupError, setTxLookupError] = useState<string | null>(null);
  const [txLookupLoading, setTxLookupLoading] = useState(false);
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
    let cancelled = false;
    setXrplHealthLoading(true);
    setXrplHealthError(false);
    apiGet<XRPLHealthResponse>("/v1/xrpl/health")
      .then((d) => {
        if (cancelled) return;
        setXrplHealth(d);
        setXrplHealthError(false);
      })
      .catch((err) => {
        console.error("Failed to fetch XRPL health:", err);
        if (cancelled) return;
        setXrplHealth(null);
        setXrplHealthError(true);
      })
      .finally(() => {
        if (!cancelled) setXrplHealthLoading(false);
      });
    return () => {
      cancelled = true;
    };
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

  const canVerifySettlement = Boolean(permit?.bundle_hash && settledTxHash.trim());

  const status = useMemo(() => {
    if (settlementResult && settlementPassed) return { label: "Verified", kind: "anchored" as const };
    if (settlementResult && !settlementPassed) return { label: "Settlement Failed", kind: "bad" as const };
    if (!permit) return { label: "No Permit", kind: "neutral" as const };
    if (remaining <= 0) return { label: "Expired", kind: "bad" as const };
    if (remaining < 60) return { label: "Expiring Soon", kind: "warn" as const };
    return { label: "Active", kind: "good" as const };
  }, [permit, remaining, settlementResult, settlementPassed]);

  const expiryPercent = useMemo(() => {
    if (!permit || remaining <= 0 || permit.expires_in_seconds <= 0) return 0;
    return Math.min(100, (remaining / permit.expires_in_seconds) * 100);
  }, [permit, remaining]);

  const regulatoryControlsJson = useMemo(() => {
    if (!permit) return "";
    return JSON.stringify({
      asset_classification: permit.bundle.asset.classification,
      regulatory_treatment: permit.bundle.asset.regulatory_treatment,
      reserve_backed: permit.bundle.constraints.reserve_backed,
      liquidity_verified: permit.bundle.constraints.liquidity_verified,
      kyc_verified: permit.bundle.constraints.kyc_verified,
      sanctions_check: permit.bundle.constraints.sanctions_check,
      jurisdiction: permit.bundle.constraints.jurisdiction,
      max_amount: permit.bundle.constraints.max_amount,
      freeze_possible: permit.bundle.constraints.freeze_possible,
      clawback_possible: permit.bundle.constraints.clawback_possible,
      trustline_required: permit.bundle.constraints.trustline_required,
    }, null, 2);
  }, [permit]);

  async function verifyPermit() {
    if (!permit) return;
    setVerifyError(null);
    setVerifyResult(null);
    setVerifyingPermit(true);

    try {
      const data = await apiPost<unknown>("/v1/verify", {
        bundle: permit.bundle,
        signature: permit.signature,
      });
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
      setVerifyError(describeError(e, "Failed to verify permit."));
    } finally {
      setVerifyingPermit(false);
    }
  }

  async function verifySettlement() {
    if (!permit?.bundle_hash || !settledTxHash.trim()) return;
    setSettlementError(null);
    setSettlementResult(null);
    setVerifying(true);

    try {
      const data = await apiPost<SettlementVerifyResponse>("/v1/settlement/verify", {
        bundle_hash: permit.bundle_hash,
        tx_hash: settledTxHash.trim(),
      });
      setSettlementResult(data);
    } catch (e: unknown) {
      setSettlementError(describeError(e, "Failed to verify settlement."));
    } finally {
      setVerifying(false);
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

  async function lookupTransaction() {
    if (!txLookupHash.trim()) return;
    setTxLookupError(null);
    setTxLookupResult(null);
    setTxLookupLoading(true);

    try {
      const data = await apiGet<TxLookupResponse>(
        `/v1/xrpl/tx/${encodeURIComponent(txLookupHash.trim())}`,
      );
      setTxLookupResult(data);
    } catch (e: unknown) {
      setTxLookupError(describeError(e, "Failed to look up transaction."));
    } finally {
      setTxLookupLoading(false);
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
          {permit && remaining > 0 && !settlementResult && (
            <span className="pillRight">{formatSeconds(remaining)}</span>
          )}
        </div>
      </header>

      <div className="adapterBar">
        <span className="adapterBarLabel">XRPL Network</span>
        {buildXrplHealthBadges(xrplHealth, xrplHealthLoading, xrplHealthError).map((badge) => (
          <span key={badge.label} className={`badge ${badge.tone}`} title={badge.label}>
            <span className="badgeDot" />
            <span className="badgeLabel">{badge.label}:</span>
            <span className="badgeValue">{badge.value}</span>
          </span>
        ))}
      </div>

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
        <XRPLPaymentPanel permit={permit} panelNumber={3} order={3} />

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

        {/* Panel 2: Check Trustline */}
        <section className="card" style={{ order: 2 }}>
          <TrustlineCheckPanel panelNumber={2} />
        </section>

        {/* Supplemental: XRPL Transaction Lookup */}
        <section className="card" style={{ order: 8 }}>
          <h2>Transaction Lookup</h2>
          <p className="muted">
            Look up a real XRPL transaction by hash to inspect its details.
          </p>

          <label className="label">Transaction Hash</label>
          <input
            className="input"
            value={txLookupHash}
            onChange={(e) => setTxLookupHash(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && txLookupHash.trim() && !txLookupLoading) lookupTransaction();
            }}
            placeholder="Enter XRPL transaction hash..."
            spellCheck={false}
          />

          <div className="row">
            <button
              className="btn primary"
              onClick={lookupTransaction}
              disabled={!txLookupHash.trim() || txLookupLoading}
            >
              {txLookupLoading ? "Looking up…" : "Look Up Transaction"}
            </button>
            <button
              className="btn"
              onClick={() => {
                setTxLookupHash("");
                setTxLookupResult(null);
                setTxLookupError(null);
              }}
            >
              Clear
            </button>
            {txLookupResult?.tx_hash && (
              <button
                className="btn"
                onClick={() => setSettledTxHash(txLookupResult.tx_hash)}
              >
                Use Hash for Verification
              </button>
            )}
          </div>

          {txLookupResult && (
            <div className="verifyResult">
              <div className={`verifyHeader ${txLookupResult.validated ? "good" : "bad"}`}>
                <span className={`verifyIcon ${txLookupResult.validated ? "good" : "bad"}`}>
                  {txLookupResult.validated ? "✔" : "✘"}
                </span>
                {txLookupResult.validated ? "Validated" : "Not Validated"}
              </div>

              <div className="verifyRows">
                <div className="verifyRow">
                  <span className="check">✔</span>
                  <span className="summaryLabel">TX Hash</span>
                  <span className="summaryValue commitValueMono breakAll">{txLookupResult.tx_hash}</span>
                  <button
                    className="copyBtn"
                    onClick={() => copyToClipboard(txLookupResult.tx_hash, "txlookup_hash")}
                    title="Copy TX hash"
                  >
                    {copied === "txlookup_hash" ? "✔ Copied" : "Copy"}
                  </button>
                </div>
                <div className="verifyRow">
                  <span className="check">✔</span>
                  <span className="summaryLabel">Type</span>
                  <span className="summaryValue">{txLookupResult.transaction_type}</span>
                </div>
                <div className="verifyRow">
                  <span className="check">✔</span>
                  <span className="summaryLabel">Account</span>
                  <span className="summaryValue commitValueMono breakAll">{txLookupResult.account}</span>
                </div>
                {txLookupResult.destination && (
                  <div className="verifyRow">
                    <span className="check">✔</span>
                    <span className="summaryLabel">Destination</span>
                    <span className="summaryValue commitValueMono breakAll">{txLookupResult.destination}</span>
                  </div>
                )}
                <div className="verifyRow">
                  <span className="check">✔</span>
                  <span className="summaryLabel">Currency</span>
                  <span className="summaryValue">{txLookupResult.amount.currency}</span>
                </div>
                <div className="verifyRow">
                  <span className="check">✔</span>
                  <span className="summaryLabel">Amount</span>
                  <span className="summaryValue">{txLookupResult.amount.value}</span>
                </div>
                {txLookupResult.amount.issuer && (
                  <div className="verifyRow">
                    <span className="check">✔</span>
                    <span className="summaryLabel">Issuer</span>
                    <span className="summaryValue commitValueMono breakAll">{txLookupResult.amount.issuer}</span>
                  </div>
                )}
                {txLookupResult.engine_result && (
                  <div className="verifyRow">
                    <span className={checkClass(txLookupResult.engine_result === "tesSUCCESS")}>
                      {checkSymbol(txLookupResult.engine_result === "tesSUCCESS")}
                    </span>
                    <span className="summaryLabel">Engine Result</span>
                    <span className="summaryValue">{txLookupResult.engine_result}</span>
                  </div>
                )}
                <div className="verifyRow">
                  <span className="check">✔</span>
                  <span className="summaryLabel">Network</span>
                  <span className="summaryValue">{txLookupResult.network}</span>
                </div>
              </div>
            </div>
          )}

          {txLookupError && (
            <StatusMessage variant="error" title="Transaction lookup failed">
              {txLookupError}
            </StatusMessage>
          )}
          {!txLookupError && txLookupLoading && (
            <StatusMessage variant="loading" title="Looking up transaction…">
              Querying the XRPL for the transaction details.
            </StatusMessage>
          )}
          {!txLookupError && !txLookupLoading && !txLookupResult && (
            <StatusMessage variant="empty" title="No transaction looked up yet">
              Enter an XRPL transaction hash above to inspect its details.
            </StatusMessage>
          )}
        </section>
      </main>

      <footer className="footer">
        <span className="muted">
          MVP · Authorization and constraints are signed and time-bound · CompliGate verifies settled XRPL outcomes
        </span>
      </footer>
    </div>
  );
}
