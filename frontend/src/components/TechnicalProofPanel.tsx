import { useMemo } from "react";

import StatusMessage from "./StatusMessage";
import PanelNumber from "./PanelNumber";
import { useCopyToClipboard } from "../lib/useCopyToClipboard";
import {
  formatCheckedAt,
  formatStatusLabel,
  outcomeClass,
  outcomeSymbol,
  outcomeTextClass,
  providerOutcome,
} from "../lib/format";
import type {
  ComplianceEvidenceItem,
  PermitResponse,
} from "../types/api";

type Props = {
  permit: PermitResponse | null;
  /** Optional panel number rendered next to the title. */
  panelNumber?: number;
  /** Optional CSS flex order, used to position among sibling panels. */
  order?: number;
};

/**
 * Render a single human-readable evidence row inside the Compliance
 * Evidence section. Used for KYC, sanctions, and reserve / liquidity.
 *
 * Each row exposes the same four fields the regulator-facing audit
 * trail cares about: provider / source, decision / status, the time
 * the check was performed, and the underlying evidence reference. We
 * render `Not Provided` for missing fields rather than fabricating a
 * value so the proof view never claims evidence that does not exist.
 */
function EvidenceRow({
  title,
  status,
  provider,
  source,
  checkedAt,
  evidenceReference,
  reasonCodes,
}: {
  title: string;
  status: string | null | undefined;
  provider?: string | null;
  source?: string | null;
  checkedAt?: number | null;
  evidenceReference?: string | null;
  reasonCodes?: string[];
}) {
  const outcome = providerOutcome(status);
  const checkedAtLabel = formatCheckedAt(checkedAt);
  return (
    <div className="evidenceItem">
      <div className="evidenceItemHeader">
        <span className={outcomeClass(outcome)}>{outcomeSymbol(outcome)}</span>
        <span className="evidenceItemTitle">{title}</span>
        <span className={`summaryValue ${outcomeTextClass(outcome)}`}>
          {formatStatusLabel(status)}
        </span>
      </div>
      <dl className="evidenceFieldList">
        <div className="evidenceField">
          <dt>Provider / Source</dt>
          <dd>
            {(() => {
              if (!provider && !source) {
                return <span className="textMuted">Not Provided</span>;
              }
              if (provider && source && source !== provider) {
                return `${provider} (${source})`;
              }
              return provider ?? source;
            })()}
          </dd>
        </div>
        <div className="evidenceField">
          <dt>Decision / Status</dt>
          <dd>{status ? String(status) : <span className="textMuted">Not Provided</span>}</dd>
        </div>
        <div className="evidenceField">
          <dt>Checked At</dt>
          <dd>
            {checkedAtLabel ?? <span className="textMuted">Not Provided</span>}
          </dd>
        </div>
        <div className="evidenceField">
          <dt>Evidence Reference</dt>
          <dd className="commitValueMono breakAll">
            {evidenceReference ? (
              evidenceReference
            ) : (
              <span className="textMuted">Not Provided</span>
            )}
          </dd>
        </div>
        {reasonCodes && reasonCodes.length > 0 && (
          <div className="evidenceField">
            <dt>Reason Codes</dt>
            <dd>{reasonCodes.join(", ")}</dd>
          </div>
        )}
      </dl>
    </div>
  );
}

/**
 * TechnicalProofPanel
 *
 * Renders the raw technical artifacts that back a compliance permit:
 * a human-readable Compliance Evidence summary (Sanctions / KYC /
 * Reserve & Liquidity) sourced from the real provider attestations,
 * followed by the bundle hash, the regulatory controls JSON
 * projection, the full proof bundle, the issuer signature, and (when
 * present) the proof artifact. Each block has a copy-to-clipboard
 * button.
 */
export default function TechnicalProofPanel({ permit, panelNumber, order }: Props) {
  const { copied, copy: copyToClipboard } = useCopyToClipboard();

  const regulatoryControlsJson = useMemo(() => {
    if (!permit) return "";
    // Project the *real* provider-backed evidence rather than just the
    // derived booleans. Each compliance dimension is rendered as an
    // explicit `{ status, reference }` so it is impossible to confuse
    // "the provider denied this" with "no provider was available", and
    // so the proof view never claims an attestation that does not
    // exist (the references are `null` in that case).
    return JSON.stringify(
      {
        asset_classification: permit.bundle.asset.classification,
        regulatory_treatment: permit.bundle.asset.regulatory_treatment,
        jurisdiction: permit.bundle.constraints.jurisdiction,
        max_amount: permit.bundle.constraints.max_amount,
        compliance: {
          kyc: {
            status: permit.summary.kyc_status,
            reference: permit.bundle.attestations.kyc_reference,
            provider:
              permit.bundle.attestations.kyc_result?.provider_name ?? null,
          },
          sanctions: {
            status: permit.summary.sanctions_status,
            reference: permit.bundle.attestations.sanctions_reference,
          },
          reserve: {
            status: permit.summary.reserve_status,
            reference: permit.bundle.attestations.reserve_reference,
            provider:
              permit.bundle.attestations.reserve_result?.provider_name ?? null,
          },
          liquidity: {
            status: permit.summary.liquidity_status,
            reference: permit.bundle.attestations.liquidity_reference,
          },
        },
        issuer_controls: {
          freeze_possible: permit.bundle.constraints.freeze_possible,
          clawback_possible: permit.bundle.constraints.clawback_possible,
          trustline_required: permit.bundle.constraints.trustline_required,
        },
        decision_result: permit.decision_result,
        reason_codes: permit.reason_codes,
      },
      null,
      2,
    );
  }, [permit]);

  // Lookup helper for the structured per-check evidence records the
  // backend emits in `bundle.compliance_evidence`. Sanctions does not
  // currently get a first-class normalized result on `attestations`
  // (unlike KYC and reserve), so we read the provider id and timestamp
  // from this list. Looking up KYC / reserve here as well lets us fall
  // back to a real `checked_at` if the normalized result is absent.
  const evidenceByCheck = useMemo(() => {
    const map = new Map<string, ComplianceEvidenceItem>();
    for (const item of permit?.bundle.compliance_evidence ?? []) {
      map.set(item.check, item);
    }
    return map;
  }, [permit]);

  return (
    <section className="card spanFull" style={order !== undefined ? { order } : undefined}>
      <h2>
        {panelNumber !== undefined && <PanelNumber n={panelNumber} />}
        Technical Proof Artifact
      </h2>
      {!permit ? (
        <StatusMessage variant="empty" title="No proof artifact yet">
          Proof and signature artifact details will appear here after a permit is issued.
        </StatusMessage>
      ) : (
        <div className="codeBlock">
          {(() => {
            const attestations = permit.bundle.attestations;
            const sanctionsItem = evidenceByCheck.get("sanctions");
            const kycItem = evidenceByCheck.get("kyc");
            const reserveItem = evidenceByCheck.get("reserve");
            const liquidityItem = evidenceByCheck.get("liquidity");

            return (
              <div className="evidenceSection">
                <div className="codeTitle">Compliance Evidence</div>

                <div className="evidenceSubheader">Sanctions Evidence</div>
                <EvidenceRow
                  title="Sanctions screening"
                  status={permit.summary.sanctions_status}
                  provider={sanctionsItem?.provider_id}
                  checkedAt={sanctionsItem?.checked_at}
                  evidenceReference={
                    attestations.sanctions_reference ??
                    sanctionsItem?.reference ??
                    null
                  }
                  reasonCodes={
                    sanctionsItem?.reason ? [sanctionsItem.reason] : undefined
                  }
                />

                <div className="evidenceSubheader">KYC Evidence</div>
                <EvidenceRow
                  title="KYC (subject)"
                  status={
                    attestations.kyc_result?.kyc_status ??
                    permit.summary.kyc_status
                  }
                  provider={
                    attestations.kyc_result?.provider_name ??
                    kycItem?.provider_id ??
                    null
                  }
                  source={attestations.kyc_result?.source_system}
                  checkedAt={
                    attestations.kyc_result?.checked_at ?? kycItem?.checked_at
                  }
                  evidenceReference={
                    attestations.kyc_result?.evidence_reference ??
                    attestations.kyc_reference ??
                    kycItem?.reference ??
                    null
                  }
                  reasonCodes={attestations.kyc_result?.reason_codes}
                />
                {attestations.kyc_destination_result && (
                  <EvidenceRow
                    title="KYC (destination)"
                    status={attestations.kyc_destination_result.kyc_status}
                    provider={attestations.kyc_destination_result.provider_name}
                    source={attestations.kyc_destination_result.source_system}
                    checkedAt={attestations.kyc_destination_result.checked_at}
                    evidenceReference={
                      attestations.kyc_destination_result.evidence_reference ??
                      attestations.kyc_destination_reference ??
                      null
                    }
                    reasonCodes={attestations.kyc_destination_result.reason_codes}
                  />
                )}

                <div className="evidenceSubheader">Reserve / Liquidity Evidence</div>
                <EvidenceRow
                  title="Reserve backing"
                  status={
                    attestations.reserve_result?.reserve_status ??
                    permit.summary.reserve_status
                  }
                  provider={
                    attestations.reserve_result?.provider_name ??
                    reserveItem?.provider_id ??
                    null
                  }
                  source={attestations.reserve_result?.attestor_name}
                  checkedAt={
                    attestations.reserve_result?.checked_at ??
                    reserveItem?.checked_at
                  }
                  evidenceReference={
                    attestations.reserve_result?.evidence_reference ??
                    attestations.reserve_reference ??
                    reserveItem?.reference ??
                    null
                  }
                  reasonCodes={attestations.reserve_result?.reason_codes}
                />
                <EvidenceRow
                  title="Liquidity"
                  status={
                    attestations.reserve_result?.liquidity_status ??
                    permit.summary.liquidity_status
                  }
                  provider={
                    attestations.reserve_result?.provider_name ??
                    liquidityItem?.provider_id ??
                    null
                  }
                  source={attestations.reserve_result?.attestor_name}
                  checkedAt={
                    attestations.reserve_result?.checked_at ??
                    liquidityItem?.checked_at
                  }
                  evidenceReference={
                    attestations.liquidity_reference ??
                    liquidityItem?.reference ??
                    null
                  }
                  reasonCodes={attestations.reserve_result?.reason_codes}
                />
              </div>
            );
          })()}

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
      )}
    </section>
  );
}
