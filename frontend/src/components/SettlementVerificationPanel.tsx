import { useEffect, useState } from "react";

import { apiPost, describeError } from "../lib/api";
import StatusMessage from "./StatusMessage";
import PanelNumber from "./PanelNumber";
import ProviderStatusSummary from "./ProviderStatusSummary";
import { useCopyToClipboard } from "../lib/useCopyToClipboard";
import {
  checkClass,
  checkSymbol,
  outcomeClass,
  outcomeLabel,
  outcomeSymbol,
  outcomeTextClass,
  unavailableReasonCodes,
  type ProviderOutcome,
} from "../lib/format";
import type { PermitResponse, SettlementVerifyResponse } from "../types/api";

/**
 * Settlement decision outcomes the panel renders distinctly.
 *
 * - `pass` — backend returned `SETTLED_COMPLIANT` (or a legacy
 *   permit/allow decision string). Rendered as PASS.
 * - `fail` — backend returned `SETTLEMENT_NON_COMPLIANT` (or any
 *   other denied/rejected decision). Rendered as FAIL.
 * - `unavailable` — verification could not produce a definitive
 *   decision (explicit `unavailable` decision, the response's
 *   `unavailable` flag, or one or more `*_UNAVAILABLE` reason codes).
 *   Rendered as an explicit warning so the UI never silently
 *   conflates "unavailable" with "pass".
 */
type SettlementOutcome = "pass" | "fail" | "unavailable";

function classifySettlement(
  result: SettlementVerifyResponse,
): SettlementOutcome {
  if (result.unavailable === true) return "unavailable";
  const decision = result.decision_result;
  const upper = typeof decision === "string" ? decision.toUpperCase() : "";
  const lower = typeof decision === "string" ? decision.toLowerCase() : "";
  if (upper === "SETTLED_COMPLIANT") return "pass";
  if (upper === "SETTLEMENT_NON_COMPLIANT") return "fail";
  if (lower === "unavailable") return "unavailable";
  if (lower === "permit" || lower === "allow" || lower === "approved") {
    return "pass";
  }
  if (unavailableReasonCodes(result.reason_codes).length > 0 && !result.denied) {
    return "unavailable";
  }
  return "fail";
}

/**
 * Single row of the "Compliance Evidence Summary".
 *
 * Each row pins one regulatory control (sanctions, KYC subject,
 * KYC destination, reserve, liquidity) to:
 *   - the normalized provider outcome (`verified` / `denied` /
 *     `unavailable` / `not_evaluated`), and
 *   - the underlying provider-backed reference, when one was emitted.
 *
 * The row is omitted entirely from the summary when no signal at all
 * is present (no reference and no status flag); we never fabricate
 * evidence the backend did not actually return.
 */
type EvidenceRow = {
  id: string;
  label: string;
  outcome: ProviderOutcome;
  reference: string | null;
};

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value : null;
}

function booleanOutcome(
  value: unknown,
  unavailable: boolean,
): ProviderOutcome | null {
  if (unavailable) return "unavailable";
  if (value === true) return "verified";
  if (value === false) return "denied";
  return null;
}

function sanctionsOutcome(
  value: unknown,
  unavailable: boolean,
): ProviderOutcome | null {
  if (unavailable) return "unavailable";
  if (value === "passed") return "verified";
  if (value === "denied") return "denied";
  if (value === "unavailable") return "unavailable";
  if (typeof value === "string" && value.trim() !== "") return "denied";
  return null;
}

/**
 * Build the compliance evidence summary rows from a settlement
 * verification response. Returns `null` when the verification did not
 * surface any evidence references for the four tracked controls; the
 * panel uses that signal to decide whether to render the section at
 * all (per the panel's "evidence-backed" emphasis).
 */
function buildEvidenceSummary(
  result: SettlementVerifyResponse,
): EvidenceRow[] | null {
  const ctx = (result.proof_artifact?.evaluation_context ?? {}) as Record<
    string,
    unknown
  >;
  const codes = result.reason_codes ?? [];
  const sanctionsUnavailable = codes.some((c) =>
    /SANCTIONS.*UNAVAILABLE/i.test(c),
  );
  const kycUnavailable = codes.some((c) => /KYC.*UNAVAILABLE/i.test(c));
  const reserveUnavailable = codes.some((c) => /RESERVE.*UNAVAILABLE/i.test(c));
  const liquidityUnavailable = codes.some((c) =>
    /LIQUIDITY.*UNAVAILABLE/i.test(c),
  );

  const candidates: Array<{
    id: string;
    label: string;
    outcome: ProviderOutcome | null;
    reference: string | null;
  }> = [
    {
      id: "sanctions",
      label: "Sanctions evidence",
      outcome: sanctionsOutcome(ctx.sanctions_check, sanctionsUnavailable),
      reference: asString(ctx.sanctions_reference),
    },
    {
      id: "kyc",
      label: "KYC evidence",
      outcome: booleanOutcome(ctx.kyc_verified, kycUnavailable),
      reference: asString(ctx.kyc_reference),
    },
    {
      id: "kyc_destination",
      label: "KYC evidence (destination)",
      // No dedicated boolean for the destination subject; the
      // reference itself attests to the destination KYC check.
      outcome: null,
      reference: asString(ctx.kyc_destination_reference),
    },
    {
      id: "reserve",
      label: "Reserve evidence",
      outcome: booleanOutcome(ctx.reserve_backed, reserveUnavailable),
      reference: asString(ctx.reserve_reference),
    },
    {
      id: "liquidity",
      label: "Liquidity evidence",
      outcome: booleanOutcome(ctx.liquidity_verified, liquidityUnavailable),
      reference: asString(ctx.liquidity_reference),
    },
  ];

  const hasAnyReference = candidates.some((c) => c.reference !== null);
  if (!hasAnyReference) return null;

  return candidates
    .filter((c) => c.reference !== null || c.outcome !== null)
    .map((c) => ({
      id: c.id,
      label: c.label,
      outcome: c.outcome ?? (c.reference ? "verified" : "not_evaluated"),
      reference: c.reference,
    }));
}

type Props = {
  permit: PermitResponse | null;
  /**
   * Settled XRPL transaction hash. Lifted to the parent so other panels
   * (e.g. transaction lookup) can populate it.
   */
  settledTxHash: string;
  onSettledTxHashChange: (value: string) => void;
  /**
   * Settlement verification result. Lifted to the parent so the page
   * header status pill can react to the verified outcome.
   */
  settlementResult: SettlementVerifyResponse | null;
  onSettlementResult: (value: SettlementVerifyResponse | null) => void;
  /** CSS flex order for the settled-tx-hash input section. */
  inputOrder?: number;
  /** CSS flex order for the verify settlement section. */
  verifyOrder?: number;
  /** Optional panel number for the settled tx hash input section. */
  inputPanelNumber?: number;
  /** Optional panel number for the verify settlement section. */
  verifyPanelNumber?: number;
};

/**
 * SettlementVerificationPanel
 *
 * Combines the two settlement-flow steps that previously lived inline in
 * App.tsx:
 *
 *   1. Provide a settled XRPL transaction hash and bind it to the active
 *      permit's bundle hash.
 *   2. Verify that settled transaction against the permit's constraints
 *      via the backend.
 *
 * The settled tx hash and the verification result are lifted to the
 * parent so the page-level orchestrator can share them with sibling
 * panels (e.g. transaction lookup, header status pill).
 */
export default function SettlementVerificationPanel({
  permit,
  settledTxHash,
  onSettledTxHashChange,
  settlementResult,
  onSettlementResult,
  inputOrder,
  verifyOrder,
  inputPanelNumber,
  verifyPanelNumber,
}: Props) {
  const [error, setError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const { copied, copy: copyToClipboard } = useCopyToClipboard();

  // Reset error/verifying state whenever the active permit changes —
  // the settled tx hash and prior result are owned by the parent and
  // are reset there as part of the permit-change flow.
  useEffect(() => {
    setError(null);
    setVerifying(false);
  }, [permit]);

  const settlementOutcome: SettlementOutcome | null = settlementResult
    ? classifySettlement(settlementResult)
    : null;
  const settlementPassed = settlementOutcome === "pass";

  const canVerifySettlement = Boolean(permit?.bundle_hash && settledTxHash.trim());

  async function verifySettlement() {
    if (!permit?.bundle_hash || !settledTxHash.trim()) return;
    setError(null);
    onSettlementResult(null);
    setVerifying(true);

    try {
      const data = await apiPost<SettlementVerifyResponse>("/v1/settlement/verify", {
        bundle_hash: permit.bundle_hash,
        tx_hash: settledTxHash.trim(),
      });
      onSettlementResult(data);
    } catch (e: unknown) {
      setError(describeError(e, "Failed to verify settlement."));
    } finally {
      setVerifying(false);
    }
  }

  return (
    <>
      {/* Step 1: Provide Settled XRPL Transaction Hash */}
      <section className="card" style={inputOrder !== undefined ? { order: inputOrder } : undefined}>
        <h2>
          {inputPanelNumber !== undefined && <PanelNumber n={inputPanelNumber} />}
          Provide Settled XRPL Transaction Hash
        </h2>
        <p className="muted">
          Settle from your own XRPL wallet, then paste the settled transaction hash for verification.
        </p>

        <label className="label">Settled Transaction Hash</label>
        <input
          className="input"
          value={settledTxHash}
          onChange={(e) => onSettledTxHashChange(e.target.value)}
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
              onSettledTxHashChange("");
              onSettlementResult(null);
              setError(null);
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

      {/* Step 2: Verify Settlement */}
      <section className="card" style={verifyOrder !== undefined ? { order: verifyOrder } : undefined}>
        <h2>
          {verifyPanelNumber !== undefined && <PanelNumber n={verifyPanelNumber} />}
          Verify Settlement
        </h2>
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
        {canVerifySettlement && !verifying && !settlementResult && !error && (
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
              <div
                className={`verifyHeader ${
                  settlementOutcome === "pass"
                    ? "good"
                    : settlementOutcome === "unavailable"
                      ? "warn"
                      : "bad"
                }`}
              >
                <span
                  className={`verifyIcon ${
                    settlementOutcome === "pass"
                      ? "good"
                      : settlementOutcome === "unavailable"
                        ? "warn"
                        : "bad"
                  }`}
                >
                  {settlementOutcome === "pass"
                    ? "✔"
                    : settlementOutcome === "unavailable"
                      ? "—"
                      : "✘"}
                </span>
                {settlementOutcome === "pass"
                  ? "PASS"
                  : settlementOutcome === "unavailable"
                    ? "UNAVAILABLE"
                    : "FAIL"}{" "}
                — {settlementResult.decision_result}
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

              {(() => {
                // Crisp, audit-oriented compliance evidence summary.
                //
                // For each tracked control (sanctions, KYC subject,
                // KYC destination, reserve, liquidity) we surface:
                //   - the normalized provider outcome (verified /
                //     denied / unavailable / not_evaluated), and
                //   - the *real* provider-backed reference recorded
                //     in `evaluation_context`, when present.
                //
                // Unavailable evidence is rendered as an explicit
                // warning so operators never read silence as success.
                // The proof artifact is verification evidence only —
                // it does not imply any on-ledger enforcement.
                const rows = buildEvidenceSummary(settlementResult);
                if (!rows) return null;
                return (
                  <div
                    className="verifyRows"
                    data-testid="proof-evidence-references"
                  >
                    <div className="reasonCodesTitle">
                      Compliance Evidence Summary (authorization /
                      verification only)
                    </div>
                    {rows.map((r) => (
                      <div className="verifyRow" key={r.id}>
                        <span className={outcomeClass(r.outcome)}>
                          {outcomeSymbol(r.outcome)}
                        </span>
                        <span className="summaryLabel">{r.label}</span>
                        <span
                          className={`summaryValue ${outcomeTextClass(r.outcome)}`}
                        >
                          {outcomeLabel(r.outcome)}
                        </span>
                        {r.reference && (
                          <span className="summaryValue commitValueMono breakAll">
                            {r.reference}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                );
              })()}

              <div className="proofArtifactBlock">
                <details className="proofArtifactDetails">
                  <summary className="proofArtifactSummary">
                    Proof Artifact (verification evidence)
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

              <ProviderStatusSummary permit={permit} />
            </div>
          );
        })()}

        {error && (
          <StatusMessage variant="error" title="Settlement verification failed">
            {error}
          </StatusMessage>
        )}
      </section>
    </>
  );
}
