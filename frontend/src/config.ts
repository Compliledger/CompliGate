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

/**
 * Default name of the HTTP header used to send the API key to the backend.
 * Must match the backend's `API_KEY_HEADER_NAME` setting.
 */
export const DEFAULT_API_KEY_HEADER = "X-API-Key";

/**
 * Name of the HTTP header the frontend uses to send the API key.
 *
 * Sourced from `VITE_API_KEY_HEADER` so deployments can match a backend that
 * has been configured with a non-default `API_KEY_HEADER_NAME`. Falls back to
 * `X-API-Key`, which is also the backend default.
 */
export const API_KEY_HEADER: string =
  ((import.meta.env.VITE_API_KEY_HEADER as string | undefined) ?? "").trim() ||
  DEFAULT_API_KEY_HEADER;

/** Default timeout (in milliseconds) applied to API requests. */
export const DEFAULT_TIMEOUT_MS = 15_000;

/**
 * Optional base URL of an XRPL transaction explorer.
 *
 * Sourced from `VITE_XRPL_EXPLORER_BASE_URL`. When set, the frontend
 * deep-links the `tx_hash` returned by the backend to
 * `${XRPL_EXPLORER_BASE_URL}/${tx_hash}`. When blank, the UI shows the
 * raw `tx_hash` as plain text instead of a link.
 *
 * Intentionally has no default: a public mainnet explorer is NOT
 * hardcoded here, since transactions submitted from a testnet/devnet
 * deployment would otherwise resolve to the wrong network.
 */
export const XRPL_EXPLORER_BASE_URL: string =
  ((import.meta.env.VITE_XRPL_EXPLORER_BASE_URL as string | undefined) ?? "")
    .trim()
    .replace(/\/+$/, "");
