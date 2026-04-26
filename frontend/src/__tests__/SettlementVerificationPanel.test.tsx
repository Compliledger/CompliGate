import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import SettlementVerificationPanel from "../components/SettlementVerificationPanel";
import type {
  PermitResponse,
  SettlementVerifyResponse,
} from "../types/api";

/**
 * Verifies that the settlement verification panel surfaces the real
 * provider-backed evidence references carried inside the proof
 * artifact's `evaluation_context` (sanctions, KYC, reserve / liquidity)
 * and renders them as authorization / verification evidence — never
 * implying an enforcement action was taken.
 */
describe("SettlementVerificationPanel — proof artifact evidence references", () => {
  const baseSettlement: SettlementVerifyResponse = {
    decision_result: "permit",
    reason_codes: [],
    bundle_hash: "bundle-hash-1",
    tx_hash: "MOCK_TX_HASH",
    proof_artifact: {
      module: "CompliGate",
      entity_id: "MOCK_TX_HASH",
      rule_version_used: "v1",
      decision_result: "permit",
      evaluation_context: {
        sanctions_reference: "sanctions://provider/abc",
        kyc_reference: "kyc://provider/subject-1",
        kyc_destination_reference: "kyc://provider/destination-1",
        reserve_reference: "reserve://attestor/xyz",
        liquidity_reference: "liquidity://attestor/xyz",
      },
      reason_codes: [],
      timestamp: 1_700_000_000,
      bundle_hash: "bundle-hash-1",
      anchor_metadata: { tx_hash: "MOCK_TX_HASH" },
    },
  };

  const permit = { bundle_hash: "bundle-hash-1" } as unknown as PermitResponse;

  it("renders evidence references from the proof artifact's evaluation_context", () => {
    render(
      <SettlementVerificationPanel
        permit={permit}
        settledTxHash="MOCK_TX_HASH"
        onSettledTxHashChange={() => {}}
        settlementResult={baseSettlement}
        onSettlementResult={() => {}}
      />,
    );

    const refs = screen.getByTestId("proof-evidence-references");
    expect(refs).toHaveTextContent("Evidence References (authorization / verification only)");
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

    // The proof artifact is rendered as verification evidence and must
    // not claim or imply that any enforcement action was performed.
    expect(document.body).not.toHaveTextContent(/enforce/i);
  });

  it("omits the evidence references section when no references are present", () => {
    const settlementWithoutRefs: SettlementVerifyResponse = {
      ...baseSettlement,
      proof_artifact: {
        ...baseSettlement.proof_artifact,
        evaluation_context: {
          sanctions_reference: null,
          kyc_reference: null,
          reserve_reference: null,
          liquidity_reference: null,
        },
      },
    };

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
});
