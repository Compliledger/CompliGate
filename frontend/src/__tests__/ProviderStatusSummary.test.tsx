import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";

import ProviderStatusSummary from "../components/ProviderStatusSummary";
import type { PermitResponse } from "../types/api";

/**
 * Tests for the compact provider status summary surfaced inside the
 * permit / settlement verification flows. The block must render a row
 * for each cross-cutting compliance provider (sanctions, KYC,
 * reserve / liquidity) carrying provider name, status, and the last
 * checked timestamp when available.
 */

const CHECKED_AT = 1_700_000_000; // 2023-11-14T22:13:20.000Z

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
        kyc_result: {
          provider_name: "AcmeKYC",
          source_system: "AcmeKYC",
          subject_id: "rSubject",
          kyc_status: "verified",
          jurisdiction: "US",
          checked_at: CHECKED_AT,
          evidence_reference: "kyc-ref-1",
          reason_codes: [],
        },
        kyc_destination_reference: null,
        kyc_destination_result: null,
        reserve_reference: "res-ref-1",
        liquidity_reference: "liq-ref-1",
        reserve_result: {
          provider_name: "AcmeAttestor",
          attestor_name: "AcmeAttestor",
          reserve_status: "verified",
          liquidity_status: "verified",
          evidence_reference: "res-ref-1",
          checked_at: CHECKED_AT,
          reason_codes: [],
        },
        sanctions_reference: "sanc-ref-1",
      },
      compliance_evidence: [
        {
          check: "sanctions",
          status: "approved",
          provider_id: "OFAC-Provider",
          reference: "sanc-ref-1",
          reason: null,
          checked_at: CHECKED_AT,
          details: {},
        },
      ],
      scope: ["issue"],
      nonce: "nonce-1",
    },
    signature: "sig",
    signed_at: CHECKED_AT,
    expires_at: CHECKED_AT + 600,
    expires_in_seconds: 600,
    bundle_hash: "0xabc",
    validity: { single_use: true },
    decision_result: "allow",
    reason_codes: [],
  };
  return { ...base, ...overrides } as PermitResponse;
}

describe("ProviderStatusSummary", () => {
  it("renders nothing when no permit is supplied", () => {
    const { container } = render(<ProviderStatusSummary permit={null} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders sanctions, KYC, and reserve/liquidity rows with provider, status, and last-checked timestamp", () => {
    render(<ProviderStatusSummary permit={buildPermit()} />);

    // The container is rendered with the canonical title.
    expect(screen.getByText("Provider Status")).toBeInTheDocument();

    const sanctionsRow = screen.getByTestId("provider-status-row-sanctions");
    const sanctionsScope = within(sanctionsRow);
    expect(sanctionsScope.getByText("Sanctions")).toBeInTheDocument();
    expect(sanctionsScope.getByText("OFAC-Provider")).toBeInTheDocument();
    expect(sanctionsScope.getByText("Verified")).toBeInTheDocument();
    expect(
      sanctionsScope.getByText("2023-11-14T22:13:20.000Z"),
    ).toBeInTheDocument();

    const kycRow = screen.getByTestId("provider-status-row-kyc");
    const kycScope = within(kycRow);
    expect(kycScope.getByText("KYC")).toBeInTheDocument();
    expect(kycScope.getByText("AcmeKYC")).toBeInTheDocument();
    expect(kycScope.getByText("Verified")).toBeInTheDocument();
    expect(kycScope.getByText("2023-11-14T22:13:20.000Z")).toBeInTheDocument();

    const reserveRow = screen.getByTestId("provider-status-row-reserve");
    const reserveScope = within(reserveRow);
    expect(reserveScope.getByText("Reserve / Liquidity")).toBeInTheDocument();
    expect(reserveScope.getByText("AcmeAttestor")).toBeInTheDocument();
    expect(reserveScope.getByText("Verified")).toBeInTheDocument();
    expect(
      reserveScope.getByText("2023-11-14T22:13:20.000Z"),
    ).toBeInTheDocument();
  });

  it("falls back to a 'No provider configured' label and omits the timestamp when evidence is missing", () => {
    const permit = buildPermit();
    permit.bundle.compliance_evidence = [];
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
    permit.summary = {
      ...permit.summary,
      kyc_status: "missing",
      sanctions_status: "missing",
      reserve_status: "missing",
      liquidity_status: "missing",
    };

    render(<ProviderStatusSummary permit={permit} />);

    // One fallback per provider row (sanctions, KYC, reserve).
    expect(screen.getAllByText("No provider configured")).toHaveLength(3);
    // Status collapses to "Not Evaluated" for a missing provider.
    expect(screen.getAllByText("Not Evaluated")).toHaveLength(3);
    // No "Last checked" rows are rendered when no timestamps are known.
    expect(screen.queryByText("Last checked")).not.toBeInTheDocument();
  });

  it("accepts a custom title", () => {
    render(
      <ProviderStatusSummary
        permit={buildPermit()}
        title="Settlement Provider Status"
      />,
    );
    expect(screen.getByText("Settlement Provider Status")).toBeInTheDocument();
  });

  it("flags the mock_trm sanctions provider with an honest notice on a passing result", () => {
    const permit = buildPermit();
    permit.bundle.compliance_evidence = [
      {
        check: "sanctions",
        status: "approved",
        provider_id: "mock_trm",
        reference: "mock:rSubject:2023-11-14T22:13:20+00:00",
        reason: null,
        checked_at: CHECKED_AT,
        details: { mode: "mock", note: "TRM integration pending" },
      },
    ];

    render(<ProviderStatusSummary permit={permit} />);

    const notice = screen.getByTestId("provider-status-mock-notice");
    // Honest disclosure of the mock nature.
    expect(notice).toHaveTextContent("Mock provider (TRM integration pending)");
    expect(notice).toHaveTextContent(
      "Simulated screening only — not real compliance.",
    );
    // The required Provider / Status / Evidence triplet is present.
    expect(screen.getByTestId("provider-status-mock-provider")).toHaveTextContent(
      "mock_trm",
    );
    expect(screen.getByTestId("provider-status-mock-decision")).toHaveTextContent(
      "PASS",
    );
    expect(screen.getByTestId("provider-status-mock-evidence")).toHaveTextContent(
      "mock:rSubject:2023-11-14T22:13:20+00:00",
    );
    // A passing mock result is *not* warning-styled.
    expect(notice.className).not.toMatch(/providerStatusMockNotice--warn/);
    expect(notice).not.toHaveAttribute("role", "alert");
  });

  it.each([
    ["denied", "DENY"],
    ["unavailable", "UNAVAILABLE"],
  ] as const)(
    "applies warning styling and shows %s as %s in the mock notice",
    (sanctionsStatus, expectedDecisionLabel) => {
      const permit = buildPermit();
      permit.summary = { ...permit.summary, sanctions_status: sanctionsStatus };
      permit.bundle.compliance_evidence = [
        {
          check: "sanctions",
          status: sanctionsStatus,
          provider_id: "mock_trm",
          reference: "mock:rSubject:2023-11-14T22:13:20+00:00",
          reason: null,
          checked_at: CHECKED_AT,
          details: { mode: "mock", note: "TRM integration pending" },
        },
      ];

      render(<ProviderStatusSummary permit={permit} />);

      const notice = screen.getByTestId("provider-status-mock-notice");
      expect(notice.className).toMatch(/providerStatusMockNotice--warn/);
      expect(notice).toHaveAttribute("role", "alert");
      expect(
        screen.getByTestId("provider-status-mock-decision"),
      ).toHaveTextContent(expectedDecisionLabel);
    },
  );

  it("does not surface a mock notice for non-mock sanctions providers", () => {
    render(<ProviderStatusSummary permit={buildPermit()} />);
    expect(
      screen.queryByTestId("provider-status-mock-notice"),
    ).not.toBeInTheDocument();
  });
});
