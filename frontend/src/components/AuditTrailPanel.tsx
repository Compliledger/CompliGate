import { useMemo, useState } from "react";

import PanelNumber from "./PanelNumber";
import { useCopyToClipboard } from "../lib/useCopyToClipboard";
import type {
  PermitResponse,
  SettlementVerifyResponse,
  XRPLPaymentResponse,
} from "../types/api";

type Props = {
  permit: PermitResponse | null;
  xrplPayment: XRPLPaymentResponse | null;
  settlement: SettlementVerifyResponse | null;
  /** Optional panel number rendered next to the title. */
  panelNumber?: number;
  /** Optional CSS flex order, used to position among sibling panels. */
  order?: number;
};

/**
 * Shape of the human-readable summary the audit trail surfaces. Built
 * up-front so the same values back the rendered rows and the audit
 * trail JSON dump shown below.
 */
type AuditTrailSummary = {
  bundle_hash: string;
  tx_hash: string;
  decision_result: string;
  rule_version_used: string;
  reason_codes: string[];
  evidence_references: Array<{ label: string; reference: string }>;
};

/**
 * Compact label/value row used by the audit trail. Mirrors the
 * `summaryRow` styling already used by `PermitSummaryPanel` so the
 * audit trail feels native alongside the other panels.
 *
 * The value is rendered as monospaced text when `mono` is set, which
 * is the right treatment for hashes and rule versions, and falls back
 * to the regular weight for plain text values like decision results.
 */
function AuditRow({
  label,
  value,
  mono = false,
  copyKey,
  copied,
  onCopy,
}: {
  label: string;
  value: string;
  mono?: boolean;
  copyKey?: string;
  copied?: string | null;
  onCopy?: (text: string, key: string) => void;
}) {
  const valueClassName = mono
    ? "summaryValue commitValueMono breakAll"
    : "summaryValue";
  return (
    <div className="summaryRow">
      <span className="summaryLabel">{label}</span>
      <span className={valueClassName}>{value}</span>
      {copyKey && onCopy && (
        <button
          className="copyBtn"
          onClick={() => onCopy(value, copyKey)}
          title={`Copy ${label.toLowerCase()}`}
        >
          {copied === copyKey ? "✔ Copied" : "Copy"}
        </button>
      )}
    </div>
  );
}

/**
 * Pull the headline tx hash for the audit trail. The XRPL payment
 * response is authoritative (it is the hash the operator submitted),
 * but we fall back to the settlement response and the proof artifact
 * anchor in case the payment was looked up rather than submitted.
 */
function pickTxHash(
  xrplPayment: XRPLPaymentResponse,
  settlement: SettlementVerifyResponse,
): string {
  if (xrplPayment.tx_hash) return xrplPayment.tx_hash;
  if (typeof settlement.tx_hash === "string" && settlement.tx_hash) {
    return settlement.tx_hash;
  }
  const anchorTxHash = settlement.proof_artifact?.anchor_metadata?.tx_hash;
  return typeof anchorTxHash === "string" ? anchorTxHash : "";
}

/**
 * Headline bundle hash for the audit trail. The settlement
 * verification carries the bundle hash that was actually verified;
 * the permit's bundle hash is the natural fallback for runs where
 * the verification response only echoes the proof artifact.
 */
function pickBundleHash(
  permit: PermitResponse,
  settlement: SettlementVerifyResponse,
): string {
  if (typeof settlement.bundle_hash === "string" && settlement.bundle_hash) {
    return settlement.bundle_hash;
  }
  const artifactHash = settlement.proof_artifact?.bundle_hash;
  if (typeof artifactHash === "string" && artifactHash) return artifactHash;
  return permit.bundle_hash;
}

/**
 * Collect the key provider evidence references that backed the
 * settlement decision. These are the same references the technical
 * proof panel exposes per check, surfaced here as a flat list so the
 * audit trail stays compact. References that were not produced by a
 * provider (i.e. `null`) are omitted — the audit trail never
 * fabricates evidence that does not exist.
 */
function pickEvidenceReferences(
  permit: PermitResponse,
  settlement: SettlementVerifyResponse,
): Array<{ label: string; reference: string }> {
  const ctx = (settlement.proof_artifact?.evaluation_context ?? {}) as Record<
    string,
    unknown
  >;
  const attestations = permit.bundle.attestations;

  // Order matches the order shown in the settlement and technical
  // proof panels so an auditor scanning across panels sees a
  // consistent layout.
  const candidates: Array<{ label: string; reference: string | null }> = [
    {
      label: "Sanctions",
      reference:
        asString(ctx.sanctions_reference) ?? attestations.sanctions_reference,
    },
    {
      label: "KYC (subject)",
      reference:
        asString(ctx.kyc_reference) ??
        attestations.kyc_result?.evidence_reference ??
        attestations.kyc_reference,
    },
    {
      label: "KYC (destination)",
      reference:
        asString(ctx.kyc_destination_reference) ??
        attestations.kyc_destination_result?.evidence_reference ??
        attestations.kyc_destination_reference,
    },
    {
      label: "Reserve",
      reference:
        asString(ctx.reserve_reference) ??
        attestations.reserve_result?.evidence_reference ??
        attestations.reserve_reference,
    },
    {
      label: "Liquidity",
      reference:
        asString(ctx.liquidity_reference) ?? attestations.liquidity_reference,
    },
  ];

  return candidates
    .filter((c): c is { label: string; reference: string } =>
      typeof c.reference === "string" && c.reference.length > 0,
    );
}

function asString(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

/**
 * AuditTrailPanel
 *
 * Renders a concise, human-readable audit trail summary for a
 * completed flow — i.e. when the user holds a permit, has submitted
 * (or looked up) the corresponding XRPL payment, and has verified the
 * resulting settlement. The panel is intentionally a no-op (renders
 * nothing) until all three artifacts are present, so it never appears
 * for partial / in-progress flows.
 *
 * The summary surfaces the audit-critical fields a regulator or
 * operator would want to capture in a single screenshot — bundle
 * hash, settled tx hash, decision result, rule version, key reason
 * codes, and the provider evidence references that backed the
 * decision — and keeps the full JSON details available below in a
 * collapsible block so the human-readable layer never hides the
 * underlying artifact.
 */
export default function AuditTrailPanel({
  permit,
  xrplPayment,
  settlement,
  panelNumber,
  order,
}: Props) {
  const { copied, copy: copyToClipboard } = useCopyToClipboard();
  const [showJson, setShowJson] = useState(false);

  const summary: AuditTrailSummary | null = useMemo(() => {
    if (!permit || !xrplPayment || !settlement) return null;

    const txHash = pickTxHash(xrplPayment, settlement);
    const bundleHash = pickBundleHash(permit, settlement);

    const decisionResult =
      settlement.decision_result ??
      settlement.proof_artifact?.decision_result ??
      "";

    const ruleVersionUsed =
      settlement.proof_artifact?.rule_version_used ??
      permit.proof_artifact?.rule_version_used ??
      permit.bundle.policy.version ??
      "";

    return {
      bundle_hash: bundleHash,
      tx_hash: txHash,
      decision_result: String(decisionResult),
      rule_version_used: String(ruleVersionUsed),
      reason_codes: settlement.reason_codes ?? [],
      evidence_references: pickEvidenceReferences(permit, settlement),
    };
  }, [permit, xrplPayment, settlement]);

  // Render nothing until all three flow artifacts are available.
  // Keeping this as an early return (rather than a placeholder card)
  // means the audit trail simply does not exist for partial flows,
  // which is the desired regulator-facing semantics.
  if (!summary || !permit || !xrplPayment || !settlement) {
    return null;
  }

  const auditTrailJson = JSON.stringify(
    {
      summary: {
        bundle_hash: summary.bundle_hash,
        tx_hash: summary.tx_hash,
        decision_result: summary.decision_result,
        rule_version_used: summary.rule_version_used,
        reason_codes: summary.reason_codes,
        evidence_references: summary.evidence_references,
      },
      permit: {
        bundle_hash: permit.bundle_hash,
        signed_at: permit.signed_at,
        expires_at: permit.expires_at,
        decision_result: permit.decision_result,
        reason_codes: permit.reason_codes,
        proof_artifact: permit.proof_artifact,
      },
      xrpl_payment: xrplPayment,
      settlement_verification: settlement,
    },
    null,
    2,
  );

  return (
    <section
      className="card spanFull"
      data-testid="audit-trail-panel"
      style={order !== undefined ? { order } : undefined}
    >
      <h2>
        {panelNumber !== undefined && <PanelNumber n={panelNumber} />}
        Audit Trail
      </h2>
      <p className="muted" style={{ marginTop: 0, fontSize: 13 }}>
        End-to-end record of this flow — permit, settled XRPL transaction, and
        settlement verification.
      </p>

      <div className="auditTrailSummary">
        <AuditRow
          label="Bundle Hash"
          value={summary.bundle_hash}
          mono
          copyKey="audit_bundle_hash"
          copied={copied}
          onCopy={copyToClipboard}
        />
        <AuditRow
          label="Transaction Hash"
          value={summary.tx_hash}
          mono
          copyKey="audit_tx_hash"
          copied={copied}
          onCopy={copyToClipboard}
        />
        <AuditRow label="Decision" value={summary.decision_result} />
        <AuditRow
          label="Rule Version"
          value={summary.rule_version_used}
          mono
        />
        <div className="summaryRow">
          <span className="summaryLabel">Reason Codes</span>
          <span className="summaryValue">
            {summary.reason_codes.length > 0 ? (
              <span className="auditTrailReasonCodes">
                {summary.reason_codes.map((code) => (
                  <span key={code} className="auditTrailReasonCode">
                    {code}
                  </span>
                ))}
              </span>
            ) : (
              <span className="textMuted">None</span>
            )}
          </span>
        </div>
        <div className="summaryRow auditTrailEvidenceRow">
          <span className="summaryLabel">Evidence References</span>
          <span className="summaryValue auditTrailEvidenceList">
            {summary.evidence_references.length > 0 ? (
              summary.evidence_references.map((ref) => (
                <span
                  key={ref.label}
                  className="auditTrailEvidenceItem"
                  data-testid={`audit-evidence-${ref.label}`}
                >
                  <span className="auditTrailEvidenceLabel">{ref.label}</span>
                  <span className="commitValueMono breakAll">
                    {ref.reference}
                  </span>
                </span>
              ))
            ) : (
              <span className="textMuted">None</span>
            )}
          </span>
        </div>
      </div>

      <div className="auditTrailDetails">
        <button
          type="button"
          className="auditTrailToggle"
          aria-expanded={showJson}
          onClick={() => setShowJson((v) => !v)}
        >
          {showJson ? "▾ Hide JSON details" : "▸ Show JSON details"}
        </button>
        {showJson && (
          <div className="codeBlock">
            <div className="codeTitleRow">
              <div className="codeTitle">Audit Trail (raw JSON)</div>
              <button
                className="copyBtn"
                onClick={() => copyToClipboard(auditTrailJson, "audit_json")}
                title="Copy audit trail JSON"
              >
                {copied === "audit_json" ? "✔ Copied" : "Copy"}
              </button>
            </div>
            <pre>{auditTrailJson}</pre>
          </div>
        )}
      </div>
    </section>
  );
}
