import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { fireEvent } from "@testing-library/react";

import PermitVerificationPanel from "../components/PermitVerificationPanel";
import type {
  PermitResponse,
  VerifyResponse,
} from "../types/api";

// Mock the API client so we can drive `/v1/verify` responses directly.
vi.mock("../lib/api", () => ({
  apiPost: vi.fn(),
  describeError: (e: unknown, fallback: string) =>
    e instanceof Error ? e.message : fallback,
}));

import { apiPost } from "../lib/api";

const apiPostMock = apiPost as unknown as ReturnType<typeof vi.fn>;

/**
 * Build a minimal `PermitResponse` shape with overridable fields so tests
 * can assert how the panel renders different authorization scenarios.
 */
function makePermit(overrides: Partial<PermitResponse> = {}): PermitResponse {
  const base: PermitResponse = {
    summary: {
      issuer_verified: true,
      asset_classification: "regulated",
      kyc_status: "approved",
      sanctions_status: "approved",
      reserve_status: "approved",
      liquidity_status: "approved",
      policy_version: "v1.0",
      expires_in_seconds: 600,
    },
    bundle: {
      bundle_id: "b-1",
      subject: "alice",
      action: "transfer",
      exp: Math.floor(Date.now() / 1000) + 600,
      asset: {
        issuer: "rIssuer",
        currency: "RLUSD",
        classification: "regulated",
        policy_id: "p-1",
      },
      constraints: { max_amount: 100 },
      policy: { version: "v1.0", jurisdiction: "US" },
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
      scope: ["transfer"],
      nonce: "n-1",
    },
    signature: "sig",
    signed_at: 1,
    expires_at: 2,
    expires_in_seconds: 600,
    bundle_hash: "h",
    validity: { single_use: false },
  };
  return { ...base, ...overrides };
}

async function clickVerify() {
  fireEvent.click(screen.getByTestId("permit-verification-submit"));
  await waitFor(() =>
    expect(screen.getByTestId("permit-verification-outcome")).toBeInTheDocument(),
  );
}

describe("PermitVerificationPanel", () => {
  beforeEach(() => {
    apiPostMock.mockReset();
  });

  it("renders PASS only when signature, expiry, and decision are all positive", async () => {
    const permit = makePermit();
    apiPostMock.mockResolvedValueOnce({
      signature_valid: true,
      not_expired: true,
      decision_result: "allow",
      reason_codes: [],
    } satisfies VerifyResponse);

    render(<PermitVerificationPanel permit={permit} />);
    await clickVerify();

    const outcome = screen.getByTestId("permit-verification-outcome");
    expect(outcome).toHaveAttribute("data-outcome", "pass");
    expect(outcome).toHaveAttribute("data-passed", "true");
    expect(outcome).toHaveTextContent("PASS");
    // Provider-backed compliance summary is rendered.
    expect(
      screen.getByTestId("permit-verification-provider-statuses"),
    ).toHaveTextContent("KYC");
    // No distinction message in the all-positive case.
    expect(
      screen.queryByTestId("permit-verification-distinction"),
    ).not.toBeInTheDocument();
  });

  it("does not PASS on a valid signature alone (no decision context)", async () => {
    apiPostMock.mockResolvedValueOnce({
      signature_valid: true,
      not_expired: true,
    } satisfies VerifyResponse);

    // No permit prop → no compliance context whatsoever.
    render(
      <PermitVerificationPanel permit={makePermit({ summary: undefined as unknown as PermitResponse["summary"] })} />,
    );
    await clickVerify();

    const outcome = screen.getByTestId("permit-verification-outcome");
    expect(outcome).toHaveAttribute("data-passed", "false");
    expect(outcome).not.toHaveTextContent("PASS");
    expect(outcome).toHaveTextContent("INCONCLUSIVE");
    expect(
      screen.getByTestId("permit-verification-distinction"),
    ).toBeInTheDocument();
  });

  it("renders INCONCLUSIVE with a clear callout when signature is valid but compliance is unavailable", async () => {
    const permit = makePermit({ unavailable: true });
    apiPostMock.mockResolvedValueOnce({
      signature_valid: true,
      not_expired: true,
      decision_result: "unavailable",
      reason_codes: ["KYC_PROVIDER_UNAVAILABLE"],
      unavailable: true,
    } satisfies VerifyResponse);

    render(<PermitVerificationPanel permit={permit} />);
    await clickVerify();

    const outcome = screen.getByTestId("permit-verification-outcome");
    expect(outcome).toHaveAttribute("data-outcome", "warn");
    expect(outcome).toHaveTextContent("INCONCLUSIVE");
    const distinction = screen.getByTestId("permit-verification-distinction");
    expect(distinction).toHaveTextContent(/could not return a definitive result/i);
    // Reason code is rendered with the warn modifier so the missing check
    // is visually called out.
    expect(screen.getByText("KYC_PROVIDER_UNAVAILABLE")).toHaveClass(
      "reasonCodeWarn",
    );
  });

  it("renders FAIL with a clear callout when signature is valid but compliance is denied", async () => {
    const permit = makePermit({ denied: true });
    apiPostMock.mockResolvedValueOnce({
      signature_valid: true,
      not_expired: true,
      decision_result: "deny",
      reason_codes: ["SANCTIONS_HIT"],
      denied: true,
    } satisfies VerifyResponse);

    render(<PermitVerificationPanel permit={permit} />);
    await clickVerify();

    const outcome = screen.getByTestId("permit-verification-outcome");
    expect(outcome).toHaveAttribute("data-outcome", "fail");
    expect(outcome).toHaveTextContent("FAIL");
    expect(
      screen.getByTestId("permit-verification-distinction"),
    ).toHaveTextContent(/policy engine denied this authorization/i);
  });

  it("renders FAIL when the signature itself is invalid", async () => {
    const permit = makePermit();
    apiPostMock.mockResolvedValueOnce({
      signature_valid: false,
      not_expired: true,
      decision_result: "allow",
    } satisfies VerifyResponse);

    render(<PermitVerificationPanel permit={permit} />);
    await clickVerify();

    const outcome = screen.getByTestId("permit-verification-outcome");
    expect(outcome).toHaveAttribute("data-outcome", "fail");
    expect(outcome).toHaveTextContent("FAIL");
  });
});
