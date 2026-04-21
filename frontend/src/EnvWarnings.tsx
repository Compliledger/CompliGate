import { API_KEY } from "./config";

/**
 * Small, non-intrusive infrastructure notice rendered near the top of the app
 * when build-time API auth configuration is missing.
 *
 * Currently surfaces a single condition:
 *   - `VITE_API_KEY` is not set in the build environment, which means the
 *     bundle ships without a default `X-API-Key`. If the backend has API
 *     auth enabled, protected actions will fail until an operator-issued
 *     key is entered via the API Settings panel.
 *
 * The notice is intentionally subtle and operator-facing (not a consumer
 * error). It never blocks rendering — it returns `null` when nothing needs
 * to be surfaced.
 */
export default function EnvWarnings() {
  if (API_KEY.length > 0) return null;

  return (
    <div className="envWarning" role="status" aria-live="polite">
      <span className="envWarningDot" aria-hidden="true" />
      <span className="envWarningText">
        <code>VITE_API_KEY</code> is not configured in this build. Protected
        backend actions may fail if API auth is enabled — set a key via{" "}
        <strong>API Settings</strong> below or rebuild with{" "}
        <code>VITE_API_KEY</code> set.
      </span>
    </div>
  );
}
