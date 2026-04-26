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
 * Four-state outcome for a provider-backed compliance check.
 *
 * The frontend renders four distinct visual states so it never
 * conflates the meaningfully different cases:
 *
 *  - `"verified"`     — the provider returned an explicit pass.
 *  - `"denied"`       — the provider returned an explicit fail.
 *  - `"unavailable"`  — a provider was wired up but could not return
 *                       a definitive answer (timeout, error, etc.).
 *  - `"not_evaluated"`— no provider was configured for this control,
 *                       so the platform did not even attempt a check.
 *
 * Only `"verified"` is styled as success. The other three are all
 * non-success and never present a green check.
 */
export type ProviderOutcome =
  | "verified"
  | "denied"
  | "unavailable"
  | "not_evaluated";

/**
 * Map a backend compliance-status string onto the four-state outcome.
 *
 * Accepts any of the vocabularies actually emitted by the backend:
 *  - cross-cutting `ProviderStatus` — `"approved" | "denied" |
 *    "unavailable" | "missing"`
 *  - KYC / reserve normalized statuses — `"verified" | "not_verified"
 *    | "unavailable"`
 *  - the sanctions constraint projection — `"passed" | "denied" |
 *    "unavailable"`
 *
 * `"missing"`, `null`, `undefined`, and anything unrecognised all map
 * to `"not_evaluated"` so the UI fails closed and never shows a
 * synthetic pass for a control the platform never actually evaluated.
 */
export function providerOutcome(
  status: string | null | undefined,
): ProviderOutcome {
  switch (status) {
    case "approved":
    case "verified":
    case "passed":
      return "verified";
    case "denied":
    case "not_verified":
      return "denied";
    case "unavailable":
      return "unavailable";
    case "missing":
      return "not_evaluated";
    default:
      return "not_evaluated";
  }
}

/** CSS class for the small check / cross / dash indicator. */
export function outcomeClass(outcome: ProviderOutcome): string {
  switch (outcome) {
    case "verified":
      return "check";
    case "denied":
      return "check checkFail";
    case "unavailable":
      return "check checkUnavailable";
    case "not_evaluated":
      return "check checkNotEvaluated";
  }
}

/** Glyph used inside the small check / cross / dash indicator. */
export function outcomeSymbol(outcome: ProviderOutcome): string {
  switch (outcome) {
    case "verified":
      return "✔";
    case "denied":
      return "✘";
    case "unavailable":
      return "—";
    case "not_evaluated":
      return "·";
  }
}

/**
 * Human-readable label for a backend compliance-status string.
 *
 * Collapses the multiple backend vocabularies into the four canonical
 * executive-friendly states: `Verified`, `Denied`, `Unavailable`,
 * `Not Evaluated`.
 */
export function formatStatusLabel(status: string | null | undefined): string {
  return outcomeLabel(providerOutcome(status));
}

/** Human-readable label for a `ProviderOutcome`. */
export function outcomeLabel(outcome: ProviderOutcome): string {
  switch (outcome) {
    case "verified":
      return "Verified";
    case "denied":
      return "Denied";
    case "unavailable":
      return "Unavailable";
    case "not_evaluated":
      return "Not Evaluated";
  }
}

/** Optional CSS modifier for the value text colour. */
export function outcomeTextClass(outcome: ProviderOutcome): string {
  switch (outcome) {
    case "verified":
      return "textGood";
    case "denied":
      return "textBad";
    case "unavailable":
      return "textWarn";
    case "not_evaluated":
      return "textMuted";
  }
}
