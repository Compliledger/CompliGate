import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";

import AuditTrailPanel from "../components/AuditTrailPanel";
import type {
  PermitResponse,
  SettlementVerifyResponse,
  XRPLPaymentResponse,
} from "../types/api";

/**
 * Tests for the AuditTrailPanel. The panel must only render once a
 * flow is complete (permit + XRPL payment + settlement verification),
 * surface the audit-critical fields in human-readable form, and keep
 * the raw JSON details available below.
 */

const CHECKED_AT = 1_700_000_000;

function buildPermit(overrides: Partial<PermitResponse> = {}): PermitResponse {
  const base: PermitResponse = {
    summary: {
      issuer_verified: true,
      asset_classification: "stablecoin",
      kyc_status: "approved",
      sanctions_status: "approved",
      reserve_status: "approved",
      liquidity_status: "approved",
      policy_version: "v1",
      expires_in_seconds: 600,
    },
    bundle: {
      bundle_id: "b-1",
      subject: "rSubject",
      action: "issue",
      exp: CHECKED_AT + 600,
      asset: {
        issuer: "rIssuer",
        currency: "RLUSD",
        classification: "stablecoin",
        regulatory_treatment: "regulated",
        policy_id: "p-1",
      },
      constraints: {
        max_amount: 1000,
        jurisdiction: "US",
        freeze_possible: true,
        clawback_possible: true,
        trustline_required: true,
      },
      policy: { version: "v1", jurisdiction: "US" },
      attestations: {
        kyc_reference: "kyc-ref-1",
        kyc_result: null,
        kyc_destination_reference: null,
        kyc_destination_result: null,
        reserve_reference: "res-ref-1",
        liquidity_reference: "liq-ref-1",
        reserve_result: null,
        sanctions_reference: "sanc-ref-1",
      },
      compliance_evidence: [],
      scope: ["issue"],
      nonce: "nonce-1",
    },
    signature: "sig",
    signed_at: CHECKED_AT,
    expires_at: CHECKED_AT + 600,
    expires_in_seconds: 600,
    bundle_hash: "0xpermit-bundle-hash",
    validity: { single_use: true },
    proof_artifact: {
      module: "permit",
      entity_id: "e-1",
      rule_version_used: "policy-v1",
      decision_result: "allow",
      evaluation_context: {},
      reason_codes: [],
      timestamp: CHECKED_AT,
      bundle_hash: "0xpermit-bundle-hash",
      anchor_metadata: {},
    },
    decision_result: "allow",
    reason_codes: [],
  };
  return { ...base, ...overrides } as PermitResponse;
}

function buildXrplPayment(
  overrides: Partial<XRPLPaymentResponse> = {},
): XRPLPaymentResponse {
  return {
    submitted: true,
    tx_hash: "0xTXHASH",
    engine_result: "tesSUCCESS",
    network: "testnet",
    currency: "RLUSD",
    issuer: "rIssuer",
    amount: "100",
    destination: "rDestination",
    proof_link: { bundle_hash: "0xpermit-bundle-hash", tx_hash: "0xTXHASH" },
    ...overrides,
  };
}

function buildSettlement(
  overrides: Partial<SettlementVerifyResponse> = {},
): SettlementVerifyResponse {
  return {
    decision_result: "SETTLED_COMPLIANT",
    reason_codes: ["SANCTIONS_PASS", "KYC_VERIFIED"],
    tx_hash: "0xTXHASH",
    bundle_hash: "0xsettlement-bundle-hash",
    proof_artifact: {
      module: "settlement",
      entity_id: "e-1",
      rule_version_used: "policy-v1",
      decision_result: "SETTLED_COMPLIANT",
      evaluation_context: {
        sanctions_reference: "sanc-ref-1",
        kyc_reference: "kyc-ref-1",
        reserve_reference: "res-ref-1",
        liquidity_reference: "liq-ref-1",
      },
      reason_codes: ["SANCTIONS_PASS", "KYC_VERIFIED"],
      timestamp: CHECKED_AT,
      bundle_hash: "0xsettlement-bundle-hash",
      anchor_metadata: { tx_hash: "0xTXHASH" },
    },
    ...overrides,
  };
}

describe("AuditTrailPanel", () => {
  it("renders nothing until permit, XRPL payment, and settlement are all present", () => {
    const { rerender, container } = render(
      <AuditTrailPanel permit={null} xrplPayment={null} settlement={null} />,
    );
    expect(container.firstChild).toBeNull();

    rerender(
      <AuditTrailPanel
        permit={buildPermit()}
        xrplPayment={null}
        settlement={null}
      />,
    );
    expect(container.firstChild).toBeNull();

    rerender(
      <AuditTrailPanel
        permit={buildPermit()}
        xrplPayment={buildXrplPayment()}
        settlement={null}
      />,
    );
    expect(container.firstChild).toBeNull();

    rerender(
      <AuditTrailPanel
        permit={buildPermit()}
        xrplPayment={buildXrplPayment()}
        settlement={buildSettlement()}
      />,
    );
    expect(screen.getByTestId("audit-trail-panel")).toBeInTheDocument();
  });

  it("renders the human-readable summary with bundle hash, tx hash, decision, rule version, reason codes, and key evidence references", () => {
    render(
      <AuditTrailPanel
        permit={buildPermit()}
        xrplPayment={buildXrplPayment()}
        settlement={buildSettlement()}
      />,
    );

    const panel = screen.getByTestId("audit-trail-panel");
    const scope = within(panel);

    // The settlement-reported bundle hash is preferred over the
    // permit's bundle hash.
    expect(scope.getByText("0xsettlement-bundle-hash")).toBeInTheDocument();
    expect(scope.getByText("0xTXHASH")).toBeInTheDocument();
    expect(scope.getByText("SETTLED_COMPLIANT")).toBeInTheDocument();
    expect(scope.getByText("policy-v1")).toBeInTheDocument();
    expect(scope.getByText("SANCTIONS_PASS")).toBeInTheDocument();
    expect(scope.getByText("KYC_VERIFIED")).toBeInTheDocument();

    // Each provider evidence reference is rendered as a row with a
    // human-readable label.
    expect(scope.getByTestId("audit-evidence-Sanctions")).toHaveTextContent(
      "sanc-ref-1",
    );
    expect(
      scope.getByTestId("audit-evidence-KYC (subject)"),
    ).toHaveTextContent("kyc-ref-1");
    expect(scope.getByTestId("audit-evidence-Reserve")).toHaveTextContent(
      "res-ref-1",
    );
    expect(scope.getByTestId("audit-evidence-Liquidity")).toHaveTextContent(
      "liq-ref-1",
    );
    // KYC (destination) had no reference; it must not be rendered.
    expect(
      scope.queryByTestId("audit-evidence-KYC (destination)"),
    ).toBeNull();
  });

  it("falls back to the permit bundle hash and the XRPL payment tx hash when the settlement omits them", () => {
    const settlement = buildSettlement({
      bundle_hash: undefined,
      tx_hash: undefined,
      proof_artifact: {
        ...buildSettlement().proof_artifact,
        bundle_hash: "",
        anchor_metadata: {},
      },
    });
    render(
      <AuditTrailPanel
        permit={buildPermit()}
        xrplPayment={buildXrplPayment({ tx_hash: "0xFROM-PAYMENT" })}
        settlement={settlement}
      />,
    );

    const panel = screen.getByTestId("audit-trail-panel");
    const scope = within(panel);
    expect(scope.getByText("0xpermit-bundle-hash")).toBeInTheDocument();
    expect(scope.getByText("0xFROM-PAYMENT")).toBeInTheDocument();
  });

  it("shows 'None' for reason codes when the settlement returned none", () => {
    render(
      <AuditTrailPanel
        permit={buildPermit()}
        xrplPayment={buildXrplPayment()}
        settlement={buildSettlement({ reason_codes: [] })}
      />,
    );
    const panel = screen.getByTestId("audit-trail-panel");
    expect(within(panel).getAllByText("None").length).toBeGreaterThan(0);
  });

  it("shows 'None' for evidence references when no provider returned one", () => {
    const permit = buildPermit();
    permit.bundle.attestations = {
      kyc_reference: null,
      kyc_result: null,
      kyc_destination_reference: null,
      kyc_destination_result: null,
      reserve_reference: null,
      liquidity_reference: null,
      reserve_result: null,
      sanctions_reference: null,
    };
    const settlement = buildSettlement({
      proof_artifact: {
        ...buildSettlement().proof_artifact,
        evaluation_context: {},
      },
    });
    render(
      <AuditTrailPanel
        permit={permit}
        xrplPayment={buildXrplPayment()}
        settlement={settlement}
      />,
    );
    const panel = screen.getByTestId("audit-trail-panel");
    // Reason codes are still present; evidence references row should
    // explicitly say "None".
    expect(within(panel).getAllByText("None").length).toBeGreaterThan(0);
  });

  it("keeps the JSON details collapsed by default and toggles on click", () => {
    render(
      <AuditTrailPanel
        permit={buildPermit()}
        xrplPayment={buildXrplPayment()}
        settlement={buildSettlement()}
      />,
    );

    expect(screen.queryByText("Audit Trail (raw JSON)")).toBeNull();
    const toggle = screen.getByRole("button", { name: /Show JSON details/i });
    expect(toggle).toHaveAttribute("aria-expanded", "false");

    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("Audit Trail (raw JSON)")).toBeInTheDocument();

    // The dumped JSON includes the headline summary fields.
    const json = screen.getByText("Audit Trail (raw JSON)").parentElement
      ?.parentElement?.querySelector("pre")?.textContent ?? "";
    expect(json).toContain("0xsettlement-bundle-hash");
    expect(json).toContain("0xTXHASH");
    expect(json).toContain("SETTLED_COMPLIANT");
    expect(json).toContain("policy-v1");

    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByText("Audit Trail (raw JSON)")).toBeNull();
  });
});
