import { describe, expect, it } from "vitest";

import {
  formatStatusLabel,
  outcomeClass,
  outcomeLabel,
  outcomeSymbol,
  outcomeTextClass,
  providerOutcome,
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
