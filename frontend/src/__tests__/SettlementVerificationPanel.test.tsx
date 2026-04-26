import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import SettlementVerificationPanel from "../components/SettlementVerificationPanel";
import type {
  PermitResponse,
  SettlementVerifyResponse,
} from "../types/api";

/**
 * Verifies that the settlement verification panel renders an
 * evidence-backed Compliance Evidence Summary derived from the proof
 * artifact's `evaluation_context` (sanctions, KYC subject, KYC
 * destination, reserve, liquidity), and that the PASS/FAIL/UNAVAILABLE
 * outcome is driven by the backend's `SETTLED_COMPLIANT` /
 * `SETTLEMENT_NON_COMPLIANT` decision strings.
 */

const permit: PermitResponse = {
  summary: {
    issuer_verified: true,
    asset_classification: "regulated_stablecoin",
    kyc_status: "approved",
    sanctions_status: "approved",
    reserve_status: "approved",
    liquidity_status: "approved",
    policy_version: "v1",
    expires_in_seconds: 600,
  },
  bundle: {
    bundle_id: "bundle-1",
    subject: "rSubject",
    action: "transfer",
    exp: 0,
    asset: {
      issuer: "rIssuer",
      currency: "RLUSD",
      classification: "regulated_stablecoin",
      policy_id: "policy-1",
    },
    constraints: { max_amount: 1000 },
    policy: { version: "v1", jurisdiction: "US" },
    attestations: {
      kyc_reference: null,
      kyc_result: null,
      kyc_destination_reference: null,
      kyc_destination_result: null,
      reserve_reference: null,
      liquidity_reference: null,
      reserve_result: null,
      sanctions_reference: null,
    },
    compliance_evidence: [],
    scope: [],
    nonce: "n",
  },
  signature: "sig",
  signed_at: 0,
  expires_at: 0,
  expires_in_seconds: 600,
  bundle_hash: "bundle-hash-1",
  validity: { single_use: true },
};

function makeSettlement(
  overrides: Partial<SettlementVerifyResponse> = {},
  contextOverrides: Record<string, unknown> = {},
): SettlementVerifyResponse {
  return {
    decision_result: "SETTLED_COMPLIANT",
    reason_codes: [],
    bundle_hash: "bundle-hash-1",
    tx_hash: "MOCK_TX_HASH",
    proof_artifact: {
      module: "CompliGate",
      entity_id: "MOCK_TX_HASH",
      rule_version_used: "v1",
      decision_result: "SETTLED_COMPLIANT",
      evaluation_context: {
        sanctions_check: "passed",
        kyc_verified: true,
        reserve_backed: true,
        liquidity_verified: true,
        sanctions_reference: "sanctions://provider/abc",
        kyc_reference: "kyc://provider/subject-1",
        kyc_destination_reference: "kyc://provider/destination-1",
        reserve_reference: "reserve://attestor/xyz",
        liquidity_reference: "liquidity://attestor/xyz",
        ...contextOverrides,
      },
      reason_codes: [],
      timestamp: 1_700_000_000,
      bundle_hash: "bundle-hash-1",
      anchor_metadata: { tx_hash: "MOCK_TX_HASH" },
    },
    ...overrides,
  };
}

describe("SettlementVerificationPanel — compliance evidence summary", () => {
  it("renders the evidence summary with references and labels for each control", () => {
    render(
      <SettlementVerificationPanel
        permit={permit}
        settledTxHash="MOCK_TX_HASH"
        onSettledTxHashChange={() => {}}
        settlementResult={makeSettlement()}
        onSettlementResult={() => {}}
      />,
    );

    const refs = screen.getByTestId("proof-evidence-references");
    expect(refs).toHaveTextContent(/Compliance Evidence Summary/i);
    expect(refs).toHaveTextContent("Sanctions evidence");
    expect(refs).toHaveTextContent("sanctions://provider/abc");
    expect(refs).toHaveTextContent("KYC evidence");
    expect(refs).toHaveTextContent("kyc://provider/subject-1");
    expect(refs).toHaveTextContent("KYC evidence (destination)");
    expect(refs).toHaveTextContent("kyc://provider/destination-1");
    expect(refs).toHaveTextContent("Reserve evidence");
    expect(refs).toHaveTextContent("reserve://attestor/xyz");
    expect(refs).toHaveTextContent("Liquidity evidence");
    expect(refs).toHaveTextContent("liquidity://attestor/xyz");

    // The proof artifact is verification evidence and must not claim
    // or imply an enforcement action was performed.
    expect(document.body).not.toHaveTextContent(/enforce/i);
  });

  it("omits the evidence summary when no references are present", () => {
    const settlementWithoutRefs = makeSettlement(
      {},
      {
        sanctions_reference: null,
        kyc_reference: null,
        kyc_destination_reference: null,
        reserve_reference: null,
        liquidity_reference: null,
      },
    );

    render(
      <SettlementVerificationPanel
        permit={permit}
        settledTxHash="MOCK_TX_HASH"
        onSettledTxHashChange={() => {}}
        settlementResult={settlementWithoutRefs}
        onSettlementResult={() => {}}
      />,
    );

    expect(screen.queryByTestId("proof-evidence-references")).toBeNull();
  });

  it("renders SETTLED_COMPLIANT as PASS", () => {
    render(
      <SettlementVerificationPanel
        permit={permit}
        settledTxHash="MOCK_TX_HASH"
        onSettledTxHashChange={() => {}}
        settlementResult={makeSettlement()}
        onSettlementResult={() => {}}
      />,
    );
    expect(screen.getByText(/PASS — SETTLED_COMPLIANT/)).toBeInTheDocument();
  });

  it("renders SETTLEMENT_NON_COMPLIANT as FAIL", () => {
    render(
      <SettlementVerificationPanel
        permit={permit}
        settledTxHash="MOCK_TX_HASH"
        onSettledTxHashChange={() => {}}
        settlementResult={makeSettlement({
          decision_result: "SETTLEMENT_NON_COMPLIANT",
          reason_codes: ["AMOUNT_EXCEEDS_LIMIT"],
        })}
        onSettlementResult={() => {}}
      />,
    );
    expect(
      screen.getByText(/FAIL — SETTLEMENT_NON_COMPLIANT/),
    ).toBeInTheDocument();
  });

  it("renders unavailable evidence as an explicit warning row", () => {
    const settlement = makeSettlement(
      {
        decision_result: "SETTLEMENT_NON_COMPLIANT",
        reason_codes: ["SANCTIONS_SCREEN_UNAVAILABLE"],
      },
      {
        sanctions_check: "unavailable",
        sanctions_reference: null,
        // Keep other refs so the summary section renders.
      },
    );
    render(
      <SettlementVerificationPanel
        permit={permit}
        settledTxHash="MOCK_TX_HASH"
        onSettledTxHashChange={() => {}}
        settlementResult={settlement}
        onSettlementResult={() => {}}
      />,
    );
    const refs = screen.getByTestId("proof-evidence-references");
    expect(refs).toHaveTextContent("Sanctions evidence");
    expect(refs).toHaveTextContent("Unavailable");
  });

  it("renders an explicit UNAVAILABLE outcome when the response is unavailable", () => {
    render(
      <SettlementVerificationPanel
        permit={permit}
        settledTxHash="MOCK_TX_HASH"
        onSettledTxHashChange={() => {}}
        settlementResult={makeSettlement({
          decision_result: "unavailable",
          unavailable: true,
        })}
        onSettlementResult={() => {}}
      />,
    );
    expect(screen.getByText(/UNAVAILABLE — unavailable/)).toBeInTheDocument();
  });
});
