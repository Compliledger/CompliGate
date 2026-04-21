/**
 * Centralized frontend configuration.
 *
 * All access to Vite build-time environment variables (`import.meta.env`)
 * should go through this module so feature code and the API client never
 * read `import.meta.env.*` directly.
 */

/**
 * Base URL of the CompliGate backend.
 * Sourced from `VITE_API_BASE`, with any trailing slashes stripped.
 * Falls back to a local-development default.
 */
export const API_BASE: string =
  (import.meta.env.VITE_API_BASE as string | undefined)?.replace(/\/+$/, "") ??
  "http://localhost:8000";

/**
 * Build-time default for the `X-API-Key` header.
 *
 * This is the value baked into the bundle via `VITE_API_KEY` (if any).
 * Runtime overrides (e.g. a user-entered key stored in `localStorage`)
 * are handled in `api.ts`; consumers that just need to know the env-provided
 * default should read this constant.
 */
export const API_KEY: string =
  ((import.meta.env.VITE_API_KEY as string | undefined) ?? "").trim();

/** Default timeout (in milliseconds) applied to API requests. */
export const DEFAULT_TIMEOUT_MS = 15_000;
