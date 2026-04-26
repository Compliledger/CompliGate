import { describe, expect, it } from "vitest";

import {
  formatStatusLabel,
  isDeniedDecision,
  outcomeClass,
  outcomeLabel,
  outcomeSymbol,
  outcomeTextClass,
  providerOutcome,
  unavailableReasonCodes,
} from "../lib/format";

/**
 * Locks in the four-state contract used by the Permit Summary panel:
 * `verified`, `denied`, `unavailable`, and `not_evaluated`. Only
 * `verified` may be presented as success — the other three must
 * remain visually distinct from a green check so the UI never renders
 * a synthetic / placeholder compliance assertion as real proof.
 */
describe("providerOutcome", () => {
  it.each([
    ["approved", "verified"],
    ["verified", "verified"],
    ["passed", "verified"],
  ] as const)("maps %s -> verified", (input, expected) => {
    expect(providerOutcome(input)).toBe(expected);
  });

  it.each([
    ["denied", "denied"],
    ["not_verified", "denied"],
  ] as const)("maps %s -> denied", (input, expected) => {
    expect(providerOutcome(input)).toBe(expected);
  });

  it("maps unavailable -> unavailable", () => {
    expect(providerOutcome("unavailable")).toBe("unavailable");
  });

  it.each([
    ["missing"],
    [null],
    [undefined],
    [""],
    ["something-unknown"],
  ])("maps %s -> not_evaluated", (input) => {
    expect(providerOutcome(input as string | null | undefined)).toBe(
      "not_evaluated",
    );
  });
});

describe("outcomeLabel / formatStatusLabel", () => {
  it("uses the four canonical labels", () => {
    expect(outcomeLabel("verified")).toBe("Verified");
    expect(outcomeLabel("denied")).toBe("Denied");
    expect(outcomeLabel("unavailable")).toBe("Unavailable");
    expect(outcomeLabel("not_evaluated")).toBe("Not Evaluated");
  });

  it("collapses backend vocabularies onto the four canonical labels", () => {
    expect(formatStatusLabel("approved")).toBe("Verified");
    expect(formatStatusLabel("passed")).toBe("Verified");
    expect(formatStatusLabel("verified")).toBe("Verified");
    expect(formatStatusLabel("not_verified")).toBe("Denied");
    expect(formatStatusLabel("denied")).toBe("Denied");
    expect(formatStatusLabel("unavailable")).toBe("Unavailable");
    expect(formatStatusLabel("missing")).toBe("Not Evaluated");
    expect(formatStatusLabel(null)).toBe("Not Evaluated");
    expect(formatStatusLabel(undefined)).toBe("Not Evaluated");
    expect(formatStatusLabel("anything-else")).toBe("Not Evaluated");
  });
});

describe("outcomeClass / outcomeSymbol / outcomeTextClass", () => {
  it("only styles `verified` as success", () => {
    expect(outcomeClass("verified")).toBe("check");
    expect(outcomeClass("denied")).toContain("checkFail");
    expect(outcomeClass("unavailable")).toContain("checkUnavailable");
    expect(outcomeClass("not_evaluated")).toContain("checkNotEvaluated");
  });

  it("uses a distinct glyph for each outcome", () => {
    const symbols = new Set([
      outcomeSymbol("verified"),
      outcomeSymbol("denied"),
      outcomeSymbol("unavailable"),
      outcomeSymbol("not_evaluated"),
    ]);
    expect(symbols.size).toBe(4);
  });

  it("only uses the success text colour for `verified`", () => {
    expect(outcomeTextClass("verified")).toBe("textGood");
    expect(outcomeTextClass("denied")).toBe("textBad");
    expect(outcomeTextClass("unavailable")).toBe("textWarn");
    expect(outcomeTextClass("not_evaluated")).toBe("textMuted");
  });
});

/**
 * Locks in the fail-closed predicates the UI uses to decide whether a
 * permit response should be presented as a denial. The frontend must
 * never treat a denied or provider-unavailable response as a passing
 * compliance check.
 */
describe("isDeniedDecision", () => {
  it.each(["allow", "permit", "approved", "Allow", "PERMIT"])(
    "treats %s as not denied",
    (input) => {
      expect(isDeniedDecision(input)).toBe(false);
    },
  );

  it.each([
    "deny",
    "denied",
    "reject",
    "rejected",
    "block",
    "blocked",
    "unavailable",
    "DENY",
  ])("treats %s as denied", (input) => {
    expect(isDeniedDecision(input)).toBe(true);
  });

  it("treats null/undefined/empty as not denied (no decision yet)", () => {
    expect(isDeniedDecision(null)).toBe(false);
    expect(isDeniedDecision(undefined)).toBe(false);
    expect(isDeniedDecision("")).toBe(false);
  });
});

describe("unavailableReasonCodes", () => {
  it("extracts the *_UNAVAILABLE codes a fail-closed denial emits", () => {
    expect(
      unavailableReasonCodes([
        "KYC_UNAVAILABLE",
        "SANCTIONS_SCREEN_UNAVAILABLE",
        "RESERVE_EVIDENCE_UNAVAILABLE",
        "KYC_PROVIDER_UNAVAILABLE",
        "AMOUNT_WITHIN_LIMIT",
        "SANCTIONS_HIT",
      ]),
    ).toEqual([
      "KYC_UNAVAILABLE",
      "SANCTIONS_SCREEN_UNAVAILABLE",
      "RESERVE_EVIDENCE_UNAVAILABLE",
      "KYC_PROVIDER_UNAVAILABLE",
    ]);
  });

  it("returns an empty list for null/undefined/empty input", () => {
    expect(unavailableReasonCodes(null)).toEqual([]);
    expect(unavailableReasonCodes(undefined)).toEqual([]);
    expect(unavailableReasonCodes([])).toEqual([]);
  });

  it("does not match codes that merely contain the substring", () => {
    expect(unavailableReasonCodes(["UNAVAILABLE_NOTE"])).toEqual([]);
  });
});
