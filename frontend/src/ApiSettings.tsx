import { useEffect, useState } from "react";

import {
  API_BASE,
  API_KEY_HEADER,
  clearApiKey,
  getApiKey,
  isUsingEnvApiKey,
  setApiKey,
  subscribeToApiKey,
} from "./lib/api";

/**
 * Compact UI for entering / clearing the API key used by the frontend when
 * talking to the CompliGate backend. The key is persisted in localStorage,
 * with a fallback to the build-time VITE_API_KEY environment variable.
 */
export default function ApiSettings() {
  const [open, setOpen] = useState(false);
  const [value, setValue] = useState("");
  const [savedKey, setSavedKey] = useState(() => getApiKey());

  useEffect(() => {
    return subscribeToApiKey(() => setSavedKey(getApiKey()));
  }, []);

  useEffect(() => {
    if (open) setValue(savedKey);
  }, [open, savedKey]);

  function maskedKey(key: string): string {
    if (!key) return "Not set";
    if (key.length <= 6) return "••••••";
    return `${key.slice(0, 3)}…${key.slice(-3)}`;
  }

  function handleSave() {
    setApiKey(value);
    setOpen(false);
  }

  function handleClear() {
    clearApiKey();
    setValue("");
  }

  const hasKey = savedKey.length > 0;
  const sourceLabel = hasKey
    ? isUsingEnvApiKey()
      ? "from env"
      : "from browser"
    : "no key";

  return (
    <div className="apiSettings">
      <div className="apiSettingsBar">
        <span className="apiSettingsLabel">Backend</span>
        <span className="apiSettingsBase" title={API_BASE}>{API_BASE}</span>
        <span className={`badge ${hasKey ? "good" : "warn"}`}>
          <span className="badgeDot" />
          API Key: {maskedKey(savedKey)}{hasKey ? ` · ${sourceLabel}` : ""}
        </span>
        <button
          type="button"
          className="btn"
          onClick={() => setOpen((v) => !v)}
        >
          {open ? "Hide" : hasKey ? "Change" : "Set API Key"}
        </button>
      </div>

      {open && (
        <div className="apiSettingsForm">
          <label className="label" htmlFor="api-key-input">API Key</label>
          <input
            id="api-key-input"
            className="input"
            type="password"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="Paste API key issued by your CompliGate operator"
            spellCheck={false}
            autoComplete="off"
          />
          <p className="muted apiSettingsHint">
            Sent as the <code>{API_KEY_HEADER}</code> header to <code>{API_BASE}</code>.
            Stored in this browser only. Leave empty to use the build-time default
            (<code>VITE_API_KEY</code>) if one was provided.
          </p>
          <div className="row">
            <button type="button" className="btn primary" onClick={handleSave}>
              Save
            </button>
            <button type="button" className="btn" onClick={handleClear} disabled={!hasKey}>
              Clear
            </button>
            <button type="button" className="btn" onClick={() => setOpen(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
