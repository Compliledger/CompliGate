/**
 * Small, shared formatting helpers used across the panel components.
 *
 * Centralized here so individual components do not redefine the same
 * presentation primitives (and so they stay visually consistent across
 * the app).
 */

/** Format a duration in seconds as "MM:SS". */
export function formatSeconds(s: number): string {
  const safe = Math.max(0, Math.floor(s));
  const mm = Math.floor(safe / 60);
  const ss = safe % 60;
  return `${String(mm).padStart(2, "0")}:${String(ss).padStart(2, "0")}`;
}

/** CSS class for the small check/cross indicator. */
export function checkClass(valid: boolean): string {
  return valid ? "check" : "check checkFail";
}

/** Glyph used inside the small check/cross indicator. */
export function checkSymbol(valid: boolean): string {
  return valid ? "✔" : "✘";
}

/**
 * Tri-state outcome for a provider-backed compliance check.
 *
 * The frontend renders three distinct visual states so it never
 * conflates "the provider denied this" with "no provider was
 * available". Anything else (including the literal `"missing"` the
 * backend reports when no provider is wired up) is treated as
 * `"unavailable"`.
 */
export type ProviderOutcome = "ok" | "denied" | "unavailable";

/**
 * Map a backend compliance-status string onto a tri-state outcome.
 *
 * Accepts any of the vocabularies actually emitted by the backend:
 *  - cross-cutting `ProviderStatus` — `"approved" | "denied" |
 *    "unavailable" | "missing"`
 *  - KYC / reserve normalized statuses — `"verified" | "not_verified"
 *    | "unavailable"`
 *  - the sanctions constraint projection — `"passed" | "denied" |
 *    "unavailable"`
 *
 * Anything unrecognised maps to `"unavailable"` so the UI fails closed
 * rather than showing a green check by accident.
 */
export function providerOutcome(
  status: string | null | undefined,
): ProviderOutcome {
  switch (status) {
    case "approved":
    case "verified":
    case "passed":
      return "ok";
    case "denied":
    case "not_verified":
      return "denied";
    default:
      return "unavailable";
  }
}

/** CSS class for the small check / cross / dash indicator. */
export function outcomeClass(outcome: ProviderOutcome): string {
  switch (outcome) {
    case "ok":
      return "check";
    case "denied":
      return "check checkFail";
    case "unavailable":
      return "check checkUnavailable";
  }
}

/** Glyph used inside the small check / cross / dash indicator. */
export function outcomeSymbol(outcome: ProviderOutcome): string {
  switch (outcome) {
    case "ok":
      return "✔";
    case "denied":
      return "✘";
    case "unavailable":
      return "—";
  }
}

/** Human-readable label for a backend compliance-status string. */
export function formatStatusLabel(status: string | null | undefined): string {
  if (!status) return "Unavailable";
  switch (status) {
    case "approved":
      return "Approved";
    case "verified":
      return "Verified";
    case "passed":
      return "Passed";
    case "denied":
      return "Denied";
    case "not_verified":
      return "Not verified";
    case "unavailable":
      return "Unavailable";
    case "missing":
      return "No provider";
    default:
      return status;
  }
}

/** Optional CSS modifier for the value text colour. */
export function outcomeTextClass(outcome: ProviderOutcome): string {
  switch (outcome) {
    case "ok":
      return "textGood";
    case "denied":
      return "textBad";
    case "unavailable":
      return "textWarn";
  }
}
