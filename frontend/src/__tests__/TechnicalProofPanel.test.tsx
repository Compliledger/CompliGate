import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";

import TechnicalProofPanel from "../components/TechnicalProofPanel";
import type { PermitResponse } from "../types/api";

/**
 * Tests for the Compliance Evidence section rendered inside the
 * Technical Proof panel. The panel must surface real provider-backed
 * evidence (provider/source, decision/status, checked_at,
 * evidence_reference) for sanctions, KYC, and reserve / liquidity, and
 * must fall back to "Not Provided" — never a synthetic placeholder —
 * when a field is absent.
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
    proof_artifact: {
      module: "permit",
      entity_id: "e-1",
      rule_version_used: "v1",
      decision_result: "allow",
      evaluation_context: {},
      reason_codes: [],
      timestamp: CHECKED_AT,
      bundle_hash: "0xabc",
      anchor_metadata: {},
    },
    decision_result: "allow",
    reason_codes: [],
  };
  return { ...base, ...overrides } as PermitResponse;
}

describe("TechnicalProofPanel — Compliance Evidence", () => {
  it("renders the empty state when no permit is present", () => {
    render(<TechnicalProofPanel permit={null} />);
    expect(screen.getByTestId("status-message")).toHaveTextContent(
      "No proof artifact yet",
    );
  });

  it("renders dedicated Sanctions / KYC / Reserve evidence sections with provider, status, checked_at, and reference", () => {
    render(<TechnicalProofPanel permit={buildPermit()} />);

    expect(screen.getByText("Sanctions Evidence")).toBeInTheDocument();
    expect(screen.getByText("KYC Evidence")).toBeInTheDocument();
    expect(screen.getByText("Reserve / Liquidity Evidence")).toBeInTheDocument();

    // KYC row carries the real KycResult fields
    const kycRow = screen.getByText("KYC (subject)").closest(".evidenceItem");
    expect(kycRow).not.toBeNull();
    const kycScope = within(kycRow as HTMLElement);
    expect(kycScope.getByText("AcmeKYC")).toBeInTheDocument();
    expect(kycScope.getByText("verified")).toBeInTheDocument();
    expect(kycScope.getByText("kyc-ref-1")).toBeInTheDocument();
    // checked_at is formatted as ISO 8601 UTC
    expect(kycScope.getByText("2023-11-14T22:13:20.000Z")).toBeInTheDocument();

    // Sanctions row pulls provider/checked_at from compliance_evidence
    const sanctionsRow = screen
      .getByText("Sanctions screening")
      .closest(".evidenceItem");
    expect(sanctionsRow).not.toBeNull();
    const sanctionsScope = within(sanctionsRow as HTMLElement);
    expect(sanctionsScope.getByText("OFAC-Provider")).toBeInTheDocument();
    expect(sanctionsScope.getByText("sanc-ref-1")).toBeInTheDocument();

    // Reserve row uses reserve_result fields
    const reserveRow = screen
      .getByText("Reserve backing")
      .closest(".evidenceItem");
    expect(reserveRow).not.toBeNull();
    const reserveScope = within(reserveRow as HTMLElement);
    expect(reserveScope.getByText("AcmeAttestor")).toBeInTheDocument();
    expect(reserveScope.getByText("res-ref-1")).toBeInTheDocument();

    // Raw JSON blocks are still present
    expect(screen.getByText("Bundle Hash (SHA-256)")).toBeInTheDocument();
    expect(screen.getByText("Regulatory Controls (JSON)")).toBeInTheDocument();
    expect(screen.getByText("Proof Bundle (raw JSON)")).toBeInTheDocument();
    expect(screen.getByText("Signature")).toBeInTheDocument();
    expect(screen.getByText("Proof Artifact")).toBeInTheDocument();
  });

  it("renders 'Not Provided' (never a synthetic placeholder) when evidence fields are missing", () => {
    const permit = buildPermit();
    // Strip every real evidence source so all fields fall back to the
    // explicit "Not Provided" state.
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
    permit.bundle.compliance_evidence = [];
    permit.summary = {
      ...permit.summary,
      kyc_status: "missing",
      sanctions_status: "missing",
      reserve_status: "missing",
      liquidity_status: "missing",
    };

    render(<TechnicalProofPanel permit={permit} />);

    // Every evidence row must show the explicit "Not Provided" fallback
    // for the four required fields, and "Not Evaluated" for the status.
    const notProvided = screen.getAllByText("Not Provided");
    // 4 rows (sanctions, kyc subject, reserve, liquidity) × 3 fields each
    // (Provider/Source, Checked At, Evidence Reference) == 12. The
    // Decision / Status field renders the raw status string ("missing"),
    // which is itself a meaningful value rather than a placeholder.
    expect(notProvided.length).toBe(12);
    // Header status pill resolves "missing" to the Not Evaluated state.
    expect(screen.getAllByText("Not Evaluated").length).toBeGreaterThanOrEqual(4);
    // The raw "missing" status is surfaced in the Decision / Status field.
    expect(screen.getAllByText("missing").length).toBeGreaterThanOrEqual(4);
  });

  it("renders the destination KYC row when a destination KYC result is present", () => {
    const permit = buildPermit();
    permit.bundle.attestations = {
      ...permit.bundle.attestations,
      kyc_destination_reference: "kyc-dest-ref",
      kyc_destination_result: {
        provider_name: "DestKYC",
        source_system: "DestKYC",
        subject_id: "rDest",
        kyc_status: "verified",
        jurisdiction: "EU",
        checked_at: CHECKED_AT,
        evidence_reference: "kyc-dest-ref",
        reason_codes: [],
      },
    };

    render(<TechnicalProofPanel permit={permit} />);

    const destRow = screen
      .getByText("KYC (destination)")
      .closest(".evidenceItem");
    expect(destRow).not.toBeNull();
    const destScope = within(destRow as HTMLElement);
    expect(destScope.getByText("DestKYC")).toBeInTheDocument();
    expect(destScope.getByText("kyc-dest-ref")).toBeInTheDocument();
  });
});
