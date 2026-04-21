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
