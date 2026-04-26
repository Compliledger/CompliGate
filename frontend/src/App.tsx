import { useEffect, useMemo, useState } from "react";

import "./App.css";
import ApiSettings from "./ApiSettings";
import EnvWarnings from "./EnvWarnings";
import AuditTrailPanel from "./components/AuditTrailPanel";
import PermitSummaryPanel, { type PermitStatus } from "./components/PermitSummaryPanel";
import PermitVerificationPanel from "./components/PermitVerificationPanel";
import RequestPermitPanel from "./components/RequestPermitPanel";
import SettlementVerificationPanel from "./components/SettlementVerificationPanel";
import TechnicalProofPanel from "./components/TechnicalProofPanel";
import TransactionLookupPanel from "./components/TransactionLookupPanel";
import TrustlineCheckPanel from "./components/TrustlineCheckPanel";
import XRPLHealthPanel from "./components/XRPLHealthPanel";
import XRPLPaymentPanel from "./components/XRPLPaymentPanel";
import { formatSeconds, isDeniedDecision, unavailableReasonCodes } from "./lib/format";
import type {
  PermitResponse,
  SettlementVerifyResponse,
  TrustlineCheckResponse,
  XRPLPaymentResponse,
} from "./types/api";

/**
 * App
 *
 * Page-level orchestrator. Owns only the state that is shared across
 * panels (the active permit, trustline and XRPL payment results, the
 * settled XRPL transaction hash and its verification result, plus a
 * one-second timer used for the expiry countdown), wires data flow
 * between panels, and renders the high level layout (header, health
 * bar, settings, panel grid, footer).
 *
 * All domain logic, fetching and presentation live in the dedicated
 * panel components under `./components/`.
 */
export default function App() {
  const [permit, setPermit] = useState<PermitResponse | null>(null);
  const [now, setNow] = useState<number>(() => Math.floor(Date.now() / 1000));
  const [settledTxHash, setSettledTxHash] = useState("");
  const [settlementResult, setSettlementResult] = useState<SettlementVerifyResponse | null>(null);
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
    if (settlementResult.unavailable === true) return false;
    const decision = settlementResult.decision_result ?? "";
    if (decision.toUpperCase() === "SETTLED_COMPLIANT") return true;
    const d = decision.toLowerCase();
    return d === "permit" || d === "allow" || d === "approved";
  }, [settlementResult]);

  const permitDenied = useMemo(() => {
    if (!permit) return false;
    if (permit.denied || permit.unavailable) return true;
    const decision = permit.decision_result ?? permit.proof_artifact?.decision_result;
    return isDeniedDecision(decision);
  }, [permit]);

  const permitUnavailableCodes = useMemo(() => {
    if (!permit) return [];
    const codes = permit.reason_codes ?? permit.proof_artifact?.reason_codes ?? [];
    return unavailableReasonCodes(codes);
  }, [permit]);

  const status = useMemo<PermitStatus>(() => {
    // Settlement outcomes take precedence: once a payment has been
    // verified (or rejected) against the permit, that is the most
    // operationally-meaningful state to surface.
    if (settlementResult && settlementPassed) return { label: "Settlement Verified", kind: "anchored" };
    if (settlementResult && !settlementPassed) return { label: "Settlement Non-Compliant", kind: "bad" };
    if (!permit) return { label: "No Permit", kind: "neutral" };
    if (permitDenied) {
      // Distinguish a substantive denial ("Authorization Denied") from
      // a fail-closed denial caused by missing provider evidence
      // ("Evidence Unavailable") so operators know whether the gate
      // refused the request on its merits or because an upstream
      // provider could not be reached.
      return {
        label: permitUnavailableCodes.length > 0 ? "Evidence Unavailable" : "Authorization Denied",
        kind: "bad",
      };
    }
    if (remaining <= 0) return { label: "Authorization Expired", kind: "bad" };
    if (remaining < 60) return { label: "Expiring Soon", kind: "warn" };
    return { label: "Authorized", kind: "good" };
  }, [permit, remaining, settlementResult, settlementPassed, permitDenied, permitUnavailableCodes]);

  function handlePermit(p: PermitResponse) {
    setPermit(p);
    setSettledTxHash("");
    setSettlementResult(null);
    setXrplPaymentResult(null);
  }

  function handleClearPermit() {
    setPermit(null);
    setSettledTxHash("");
    setSettlementResult(null);
    setXrplPaymentResult(null);
  }

  return (
    <div className="page">
      <header className="header">
        <div className="brand">
          <div className="title">
            <span className="titleAccent">Compli</span>Gate
          </div>
          <div className="subtitle">Compliance authorization and verification layer</div>
        </div>

        <div className={`pill ${status.kind}`}>
          <span className="dot" />
          {status.label}
          {permit && remaining > 0 && !settlementResult && !permitDenied && (
            <span className="pillRight">{formatSeconds(remaining)}</span>
          )}
        </div>
      </header>

      <XRPLHealthPanel />

      <EnvWarnings />

      <ApiSettings />

      <main className="grid">
        {/* Panel 1: Request Permit */}
        <RequestPermitPanel onPermit={handlePermit} onClear={handleClearPermit} />

        {/* Panel 2: Check Trustline */}
        <section className="card" style={{ order: 2 }}>
          <TrustlineCheckPanel
            panelNumber={2}
            result={trustlineResult}
            onResult={setTrustlineResult}
          />
        </section>

        {/* Panel 3: Submit XRPL Payment */}
        <XRPLPaymentPanel
          permit={permit}
          panelNumber={3}
          order={3}
          result={xrplPaymentResult}
          onResult={setXrplPaymentResult}
        />

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
        <PermitSummaryPanel
          permit={permit}
          status={status}
          remaining={remaining}
          settlementResult={settlementResult}
          order={7}
        />

        {/* Panel 8: Transaction Lookup (supplemental) */}
        <TransactionLookupPanel onUseHash={setSettledTxHash} order={8} />

        {/* Panel 9: Technical Proof Artifact */}
        <TechnicalProofPanel permit={permit} order={9} />

        {/* Panel 10: Audit Trail (only renders when the flow is complete) */}
        <AuditTrailPanel
          permit={permit}
          xrplPayment={xrplPaymentResult}
          settlement={settlementResult}
          panelNumber={10}
          order={10}
        />
      </main>

      <footer className="footer">
        <span className="muted">
          Authorization and constraints are signed and time-bound · CompliGate verifies settled XRPL outcomes
        </span>
      </footer>
    </div>
  );
}
