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

type XrplPaymentResponse = {
  tx_hash: string;
  engine_result: string;
  amount: string;
  issuer: string;
  currency: string;
  destination: string;
  proof_link?: {
    bundle_hash: string;
    tx_hash: string;
  };
};

type SettlementVerifyNewResponse = {
  decision_result: string;
  reason_codes: string[];
  proof_artifact: Record<string, unknown>;
};

type XrplHealth = {
  configured: boolean;
  reachable: boolean;
  network: string;
  rlusd_configured: boolean;
  demo_wallet_configured: boolean;
};

type TrustlineCheckResponse = {
  trustline_exists: boolean;
  issuer: string | null;
  currency: string | null;
  raw_lines_checked: number;
};

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
  return health.configured ? "Configured" : "Not Configured";
}

function xrplReachableLabel(health: XrplHealth | null): string {
  if (!health) return "Checking...";
  return health.reachable ? "Reachable" : "Unreachable";
}

function xrplNetworkLabel(health: XrplHealth | null): string {
  if (!health) return "Checking...";
  return health.network || "Unknown";
}

function demoWalletLabel(health: XrplHealth | null): string {
  if (!health) return "Checking...";
  return health.demo_wallet_configured ? "Demo Wallet Configured" : "Demo Wallet Not Configured";
}

function PanelNumber({ n }: { n: number }) {
  return <span className="panelNumber">{n}</span>;
}

export default function App() {
  const [permit, setPermit] = useState<PermitResponse | null>(null);
  const [now, setNow] = useState<number>(() => Math.floor(Date.now() / 1000));
  const [verifyResult, setVerifyResult] = useState<VerifyResponse | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [xrplHealth, setXrplHealth] = useState<XrplHealth | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [destination, setDestination] = useState("");
  const [amount, setAmount] = useState("");
  const [paymentResult, setPaymentResult] = useState<XrplPaymentResponse | null>(null);
  const [paymentError, setPaymentError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [settlementResult, setSettlementResult] = useState<SettlementVerifyNewResponse | null>(null);
  const [settlementError, setSettlementError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [trustlineAddress, setTrustlineAddress] = useState("");
  const [trustlineResult, setTrustlineResult] = useState<TrustlineCheckResponse | null>(null);
  const [trustlineError, setTrustlineError] = useState<string | null>(null);
  const [trustlineLoading, setTrustlineLoading] = useState(false);
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
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    fetch(`${API_BASE}/v1/xrpl/health`, { signal: controller.signal })
      .then((r) => r.json())
      .then((d: XrplHealth) => setXrplHealth(d))
      .catch((err) => {
        console.error("Failed to fetch XRPL health:", err);
        setXrplHealth({
          configured: false,
          reachable: false,
          network: "",
          rlusd_configured: false,
          demo_wallet_configured: false,
        });
      })
      .finally(() => clearTimeout(timeout));
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

  async function submitXrplPayment() {
    if (!destination.trim() || !amount.trim()) return;
    setPaymentError(null);
    setPaymentResult(null);
    setSubmitting(true);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const payload: Record<string, string> = {
        destination: destination.trim(),
        amount: amount.trim(),
      };
      if (permit?.bundle_hash) {
        payload.memo_bundle_hash = permit.bundle_hash;
      }

      const res = await fetch(`${API_BASE}/v1/xrpl/payment`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      const data = await res.json();
      if (!res.ok) {
        setPaymentError(extractErrorMessage(data, "Failed to submit XRPL payment."));
      } else {
        setPaymentResult(data as XrplPaymentResponse);
      }
    } catch (e: unknown) {
      if (e instanceof Error && e.name === "AbortError") {
        setPaymentError("Request timed out. Please try again.");
      } else {
        setPaymentError(e instanceof Error ? e.message : "Network error calling XRPL payment endpoint.");
      }
    } finally {
      clearTimeout(timeout);
      setSubmitting(false);
    }
  }

  async function verifySettlement() {
    if (!permit || !paymentResult) return;
    setSettlementError(null);
    setSettlementResult(null);
    setVerifying(true);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(`${API_BASE}/v1/settlement/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          bundle_hash: permit.bundle_hash,
          tx_hash: paymentResult.tx_hash,
        }),
        signal: controller.signal,
      });

      const data = await res.json();
      if (!res.ok) {
        setSettlementError(extractErrorMessage(data, "Failed to verify settlement."));
      } else {
        setSettlementResult(data as SettlementVerifyNewResponse);
      }
    } catch (e: unknown) {
      if (e instanceof Error && e.name === "AbortError") {
        setSettlementError("Request timed out. Please try again.");
      } else {
        setSettlementError(e instanceof Error ? e.message : "Network error calling settlement verify endpoint.");
      }
    } finally {
      clearTimeout(timeout);
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

  async function checkTrustlines() {
    if (!trustlineAddress.trim()) return;
    setTrustlineError(null);
    setTrustlineResult(null);
    setTrustlineLoading(true);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(`${API_BASE}/v1/xrpl/trustline/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address: trustlineAddress.trim() }),
        signal: controller.signal,
      });
      const data = await res.json();
      if (!res.ok) {
        setTrustlineError(extractErrorMessage(data, "Failed to check trustline."));
      } else {
        setTrustlineResult(data as TrustlineCheckResponse);
      }
    } catch (e: unknown) {
      if (e instanceof Error && e.name === "AbortError") {
        setTrustlineError("Request timed out. Please try again.");
      } else {
        setTrustlineError(e instanceof Error ? e.message : "Network error checking trustline.");
      }
    } finally {
      clearTimeout(timeout);
      setTrustlineLoading(false);
    }
  }

  async function lookupTransaction() {
    if (!txLookupHash.trim()) return;
    setTxLookupError(null);
    setTxLookupResult(null);
    setTxLookupLoading(true);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(
        `${API_BASE}/v1/xrpl/tx/${encodeURIComponent(txLookupHash.trim())}`,
        { signal: controller.signal },
      );
      const data = await res.json();
      if (!res.ok) {
        setTxLookupError(extractErrorMessage(data, "Failed to look up transaction."));
      } else {
        setTxLookupResult(data as TxLookupResponse);
      }
    } catch (e: unknown) {
      if (e instanceof Error && e.name === "AbortError") {
        setTxLookupError("Request timed out. Please try again.");
      } else {
        setTxLookupError(e instanceof Error ? e.message : "Network error looking up transaction.");
      }
    } finally {
      clearTimeout(timeout);
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
        <span className={`badge ${xrplHealth === null ? "neutral" : xrplHealth.configured ? "good" : "bad"}`}>
          <span className="badgeDot" />
          {xrplConfiguredLabel(xrplHealth)}
        </span>
        <span className={`badge ${xrplHealth === null ? "neutral" : xrplHealth.reachable ? "good" : "bad"}`}>
          <span className="badgeDot" />
          {xrplReachableLabel(xrplHealth)}
        </span>
        <span className="badge neutral">
          <span className="badgeDot" />
          {xrplNetworkLabel(xrplHealth)}
        </span>
        <span className={`badge ${xrplHealth === null ? "neutral" : xrplHealth.rlusd_configured ? "good" : "bad"}`}>
          <span className="badgeDot" />
          {xrplHealth === null ? "Checking..." : xrplHealth.rlusd_configured ? "RLUSD Configured" : "RLUSD Not Configured"}
        </span>
        <span className={`badge ${xrplHealth === null ? "neutral" : xrplHealth.demo_wallet_configured ? "good" : "bad"}`}>
          <span className="badgeDot" />
          {demoWalletLabel(xrplHealth)}
        </span>
      </div>

      <main className="grid">
        {/* Panel 1: Request Permit */}
        <RequestPermitPanel
          onPermit={(p) => {
            setPermit(p);
            setVerifyResult(null);
            setVerifyError(null);
            setPaymentResult(null);
            setPaymentError(null);
            setSettlementResult(null);
            setSettlementError(null);
          }}
          onClear={() => {
            setPermit(null);
            setVerifyResult(null);
            setVerifyError(null);
            setPaymentResult(null);
            setPaymentError(null);
            setSettlementResult(null);
            setSettlementError(null);
            setDestination("");
            setAmount("");
          }}
        />

        {/* Panel 2: Show Constraints */}
        <section className="card">
          <div className="summaryHeader">
            <h2><PanelNumber n={2} />Constraints</h2>
            <span className={`badge ${status.kind}`}>
              <span className="badgeDot" />
              {status.label}
            </span>
          </div>

          {!permit ? (
            <p className="muted">Request a permit to view the constraints.</p>
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
        <section className="card">
          <h2><PanelNumber n={3} />Submit XRPL Payment</h2>
          <p className="muted">
            Submit an XRPL payment transaction. If a permit exists, its bundle hash will be included as a memo.
          </p>

          <label className="label">Destination</label>
          <input
            className="input"
            value={destination}
            onChange={(e) => setDestination(e.target.value)}
            placeholder="Enter destination address..."
            spellCheck={false}
          />

          <label className="label">Amount</label>
          <input
            className="input"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            placeholder="Enter amount..."
            spellCheck={false}
          />

          <div className="row">
            <button
              className="btn primary"
              onClick={submitXrplPayment}
              disabled={!destination.trim() || !amount.trim() || submitting}
            >
              {submitting ? "Submitting…" : "Submit XRPL Payment"}
            </button>
          </div>

          {paymentResult && (
            <div className="commitResult">
              <div className="commitResultHeader">
                <span className="badge anchored">
                  <span className="badgeDot" />
                  Payment Submitted
                </span>
              </div>

              <div className="commitRows">
                <div className="commitRow">
                  <span className="commitLabel">TX Hash</span>
                  <span className="commitValue commitValueMono" style={{ wordBreak: "break-all" }}>
                    {paymentResult.tx_hash}
                  </span>
                </div>
                <div className="commitRow">
                  <span className="commitLabel">Engine Result</span>
                  <span className="commitValue">{paymentResult.engine_result}</span>
                </div>
                <div className="commitRow">
                  <span className="commitLabel">Amount</span>
                  <span className="commitValue">{paymentResult.amount}</span>
                </div>
                <div className="commitRow">
                  <span className="commitLabel">Issuer</span>
                  <span className="commitValue commitValueMono" style={{ wordBreak: "break-all" }}>
                    {paymentResult.issuer}
                  </span>
                </div>
                <div className="commitRow">
                  <span className="commitLabel">Currency</span>
                  <span className="commitValue">{paymentResult.currency}</span>
                </div>
                <div className="commitRow">
                  <span className="commitLabel">Destination</span>
                  <span className="commitValue commitValueMono" style={{ wordBreak: "break-all" }}>
                    {paymentResult.destination}
                  </span>
                </div>
                {paymentResult.proof_link && (
                  <div className="commitRow">
                    <span className="commitLabel">Proof Link</span>
                    <span className="commitValue commitValueMono" style={{ wordBreak: "break-all" }}>
                      {paymentResult.proof_link.bundle_hash} → {paymentResult.proof_link.tx_hash}
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}

          {paymentError && <div className="alert bad">{paymentError}</div>}
        </section>

        {/* Panel 4: Verify Settlement */}
        <section className="card">
          <h2><PanelNumber n={4} />Verify Settlement</h2>
          <p className="muted">
            Verify that the XRPL payment satisfies the permit constraints.
          </p>

          <div className="row">
            <button
              className="btn primary"
              onClick={verifySettlement}
              disabled={!permit || !paymentResult || verifying}
            >
              {verifying ? "Verifying…" : "Verify Settlement"}
            </button>
          </div>

          {settlementResult && (() => {
            const artifact = settlementResult.proof_artifact;
            // Prefer hashes from the proof artifact; fall back to local state if the API omits them
            const txHash = typeof artifact.tx_hash === "string" ? artifact.tx_hash : paymentResult?.tx_hash;
            const bundleHash = typeof artifact.bundle_hash === "string" ? artifact.bundle_hash : permit?.bundle_hash;
            return (
              <div className="verifyResult">
                <div className={`verifyHeader ${settlementPassed ? "good" : "bad"}`}>
                  <span className={`verifyIcon ${settlementPassed ? "good" : "bad"}`}>
                    {settlementPassed ? "✔" : "✘"}
                  </span>
                  {settlementPassed ? "PASS" : "FAIL"} — {settlementResult.decision_result}
                </div>

                <div className="verifyRows">
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

                {settlementResult.reason_codes.length > 0 && (
                  <div className="reasonCodes">
                    <div className="reasonCodesTitle">Reason Codes</div>
                    <div className="reasonCodesList">
                      {settlementResult.reason_codes.map((rc) => (
                        <span key={rc} className="reasonCode">{rc}</span>
                      ))}
                    </div>
                  </div>
                )}

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
          {settlementResult && (
            <div className="verifyResult">
              <div className={`verifyHeader ${settlementPassed ? "good" : "bad"}`}>
                <span className={`verifyIcon ${settlementPassed ? "good" : "bad"}`}>
                  {settlementPassed ? "✔" : "✘"}
                </span>
                {settlementPassed ? "PASS" : "FAIL"}
              </div>

              <div className="verifyRows">
                <div className="verifyRow">
                  <span className={checkClass(settlementPassed)}>
                    {checkSymbol(settlementPassed)}
                  </span>
                  <span className="summaryLabel">Decision result</span>
                  <span className={`summaryValue${settlementPassed ? " textGood" : " textBad"}`}>
                    {settlementResult.decision_result}
                  </span>
                </div>

                {paymentResult?.tx_hash && (
                  <div className="verifyRow">
                    <span className="check">✔</span>
                    <span className="summaryLabel">TX hash</span>
                    <span className="summaryValue commitValueMono breakAll">
                      {paymentResult.tx_hash}
                    </span>
                    <button
                      className="copyBtn"
                      onClick={() => copyToClipboard(paymentResult.tx_hash, "settlement_tx_hash")}
                      title="Copy TX hash"
                    >
                      {copied === "settlement_tx_hash" ? "✔ Copied" : "Copy"}
                    </button>
                  </div>
                )}

                {permit?.bundle_hash && (
                  <div className="verifyRow">
                    <span className="check">✔</span>
                    <span className="summaryLabel">Bundle hash</span>
                    <span className="summaryValue commitValueMono breakAll">
                      {permit.bundle_hash}
                    </span>
                    <button
                      className="copyBtn"
                      onClick={() => copyToClipboard(permit.bundle_hash, "settlement_bundle_hash")}
                      title="Copy bundle hash"
                    >
                      {copied === "settlement_bundle_hash" ? "✔ Copied" : "Copy"}
                    </button>
                  </div>
                )}
              </div>

              {settlementResult.reason_codes.length > 0 && (
                <div className="reasonCodes">
                  <div className="reasonCodesTitle">Reason codes</div>
                  <div className="reasonCodesList">
                    {settlementResult.reason_codes.map((rc) => (
                      <span key={rc} className="reasonCode">{rc}</span>
                    ))}
                  </div>
                </div>
              )}

              <details className="proofArtifactDetails">
                <summary className="proofArtifactSummary">
                  Proof Artifact
                  <button
                    className="copyBtn"
                    onClick={(e) => {
                      e.preventDefault();
                      copyToClipboard(JSON.stringify(settlementResult.proof_artifact, null, 2), "settlement_proof");
                    }}
                    title="Copy proof artifact"
                  >
                    {copied === "settlement_proof" ? "✔ Copied" : "Copy"}
                  </button>
                </summary>
                <div className="proofArtifactBody">
                  <pre>{JSON.stringify(settlementResult.proof_artifact, null, 2)}</pre>
                </div>
              </details>
            </div>
          )}

          {settlementError && <div className="alert bad">{settlementError}</div>}
        </section>

        {/* Panel 5: Show Proof */}
        <section className="card spanFull">
          <h2><PanelNumber n={5} />Show Proof</h2>
          {!permit ? (
            <p className="muted">
              Proof bundle details will appear here after a permit is issued.
            </p>
          ) : (
            <>
              <div className="row" style={{ marginTop: 0 }}>
                <button className="btn primary" onClick={verifyPermit} disabled={!permit}>
                  Verify Permit Signature
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

        {/* Panel 6: XRPL Trustline Check */}
        <section className="card">
          <h2><PanelNumber n={6} />XRPL Trustline Check</h2>
          <p className="muted">
            Check whether an XRPL address currently has the expected trustline.
          </p>

          <label className="label">Account Address</label>
          <input
            className="input"
            value={trustlineAddress}
            onChange={(e) => setTrustlineAddress(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && trustlineAddress.trim() && !trustlineLoading) checkTrustlines();
            }}
            placeholder="r..."
            spellCheck={false}
          />

          <div className="row">
            <button
              className="btn primary"
              onClick={checkTrustlines}
              disabled={!trustlineAddress.trim() || trustlineLoading}
            >
              {trustlineLoading ? "Checking…" : "Check Trustline"}
            </button>
            <button
              className="btn"
              onClick={() => {
                setTrustlineAddress("");
                setTrustlineResult(null);
                setTrustlineError(null);
              }}
            >
              Clear
            </button>
          </div>

          {trustlineResult && (
            <div className="verifyResult">
              <div className={`verifyHeader ${trustlineResult.trustline_exists ? "good" : "bad"}`}>
                <span className={`verifyIcon ${trustlineResult.trustline_exists ? "good" : "bad"}`}>
                  {trustlineResult.trustline_exists ? "✔" : "✘"}
                </span>
                {trustlineResult.trustline_exists ? "Trustline Found" : "Trustline Not Found"}
              </div>

              <div className="verifyRows">
                <div className="verifyRow">
                  <span className={checkClass(trustlineResult.trustline_exists)}>
                    {checkSymbol(trustlineResult.trustline_exists)}
                  </span>
                  <span className="summaryLabel">Trustline Exists</span>
                  <span className="summaryValue">{trustlineResult.trustline_exists ? "Yes" : "No"}</span>
                </div>
                <div className="verifyRow">
                  <span className={checkClass(Boolean(trustlineResult.issuer))}>
                    {checkSymbol(Boolean(trustlineResult.issuer))}
                  </span>
                  <span className="summaryLabel">Issuer</span>
                  <span className="summaryValue commitValueMono breakAll">
                    {trustlineResult.issuer ?? "—"}
                  </span>
                </div>
                <div className="verifyRow">
                  <span className={checkClass(Boolean(trustlineResult.currency))}>
                    {checkSymbol(Boolean(trustlineResult.currency))}
                  </span>
                  <span className="summaryLabel">Currency</span>
                  <span className="summaryValue">{trustlineResult.currency ?? "—"}</span>
                </div>
                <div className="verifyRow">
                  <span className={checkClass(true)}>
                    {checkSymbol(true)}
                  </span>
                  <span className="summaryLabel">Raw Lines Checked</span>
                  <span className="summaryValue">{trustlineResult.raw_lines_checked}</span>
                </div>
              </div>
            </div>
          )}

          {trustlineError && <div className="alert bad">{trustlineError}</div>}
        </section>

        {/* Panel 7: XRPL Transaction Lookup */}
        <section className="card">
          <h2><PanelNumber n={7} />Transaction Lookup</h2>
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

          {txLookupError && <div className="alert bad">{txLookupError}</div>}
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
