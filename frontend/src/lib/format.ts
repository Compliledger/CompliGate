/**
 * Small, shared formatting helpers used across the panel components.
 *
 * Centralized here so individual components do not redefine the same
 * presentation primitives (and so they stay visually consistent across
 * the app).
 */

/**
 * Format a compliance "checked_at" unix timestamp (seconds) as an ISO
 * 8601 UTC string. Returns `null` for missing or non-finite values so
 * callers can decide whether to render a fallback / hide the row.
 */
export function formatCheckedAt(
  checkedAt: number | null | undefined,
): string | null {
  if (typeof checkedAt !== "number" || !Number.isFinite(checkedAt)) {
    return null;
  }
  // Backend providers emit `checked_at` as unix seconds; if a millisecond
  // value sneaks through (>= ~year 2100 in seconds) treat it as ms so we
  // never render a date in the year 50000+.
  const ms = checkedAt > 1e12 ? checkedAt : checkedAt * 1000;
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString();
}

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

const DENIED_DECISIONS = new Set([
  "deny",
  "denied",
  "reject",
  "rejected",
  "block",
  "blocked",
  "unavailable",
]);

/**
 * True when the backend's `decision_result` represents a denied or
 * not-issued permit. The backend may return any of `"deny"`, `"denied"`,
 * `"reject"`, etc.; everything that is not an explicit allow is treated
 * as denied so the UI fails closed.
 */
export function isDeniedDecision(decision: string | null | undefined): boolean {
  if (!decision) return false;
  const d = decision.toLowerCase();
  if (d === "allow" || d === "permit" || d === "approved") return false;
  return DENIED_DECISIONS.has(d);
}

/**
 * Filter a list of reason codes down to the ones that signal a
 * provider check could not be performed (e.g. `KYC_UNAVAILABLE`,
 * `SANCTIONS_SCREEN_UNAVAILABLE`, `RESERVE_EVIDENCE_UNAVAILABLE`,
 * `*_PROVIDER_UNAVAILABLE`). Used to render fail-closed denials with
 * the specific missing checks called out.
 */
export function unavailableReasonCodes(
  reasonCodes: readonly string[] | null | undefined,
): string[] {
  if (!reasonCodes) return [];
  return reasonCodes.filter((rc) => /UNAVAILABLE$/.test(rc));
}

/**
 * Outcome of a settled XRPL transaction's compliance verification.
 *
 * Mirrors the `SettlementVerifyResponse` decision vocabulary but
 * collapsed into the three operationally distinct states the UI
 * cares about.
 */
export type SettlementOutcome = "pass" | "fail" | "unavailable";

/**
 * Classify a settlement verification response into a `SettlementOutcome`.
 *
 * Keeps the unavailable branch explicit so the UI never silently
 * conflates "could not verify" with "verified compliant".
 */
export function classifySettlement(result: {
  decision_result?: string | null;
  reason_codes?: readonly string[] | null;
  unavailable?: boolean;
  denied?: boolean;
}): SettlementOutcome {
  if (result.unavailable === true) return "unavailable";
  const decision = result.decision_result;
  const upper = typeof decision === "string" ? decision.toUpperCase() : "";
  const lower = typeof decision === "string" ? decision.toLowerCase() : "";
  if (upper === "SETTLED_COMPLIANT") return "pass";
  if (upper === "SETTLEMENT_NON_COMPLIANT") return "fail";
  if (lower === "unavailable") return "unavailable";
  if (lower === "permit" || lower === "allow" || lower === "approved") {
    return "pass";
  }
  if (unavailableReasonCodes(result.reason_codes ?? null).length > 0 && !result.denied) {
    return "unavailable";
  }
  return "fail";
}
