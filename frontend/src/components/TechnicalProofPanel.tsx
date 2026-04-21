import { useMemo } from "react";

import StatusMessage from "./StatusMessage";
import PanelNumber from "./PanelNumber";
import { useCopyToClipboard } from "../lib/useCopyToClipboard";
import type { PermitResponse } from "../types/api";

type Props = {
  permit: PermitResponse | null;
  /** Optional panel number rendered next to the title. */
  panelNumber?: number;
  /** Optional CSS flex order, used to position among sibling panels. */
  order?: number;
};

/**
 * TechnicalProofPanel
 *
 * Renders the raw technical artifacts that back a compliance permit:
 * the bundle hash, the regulatory controls JSON projection, the full
 * proof bundle, the issuer signature, and (when present) the proof
 * artifact. Each block has a copy-to-clipboard button.
 */
export default function TechnicalProofPanel({ permit, panelNumber, order }: Props) {
  const { copied, copy: copyToClipboard } = useCopyToClipboard();

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
