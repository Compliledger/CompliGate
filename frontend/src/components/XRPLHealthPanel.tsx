import { useEffect, useState } from "react";

import { apiGet } from "../lib/api";
import type { XRPLHealthResponse } from "../types/api";

type BadgeTone = "neutral" | "good" | "warn" | "bad";

type HealthBadge = {
  label: string;
  value: string;
  tone: BadgeTone;
};

function buildXrplHealthBadges(
  health: XRPLHealthResponse | null,
  loading: boolean,
  errored: boolean,
): HealthBadge[] {
  if (loading) {
    return [
      { label: "Configured", value: "Loading…", tone: "neutral" },
      { label: "Reachable", value: "Loading…", tone: "neutral" },
      { label: "Network", value: "Loading…", tone: "neutral" },
      { label: "RLUSD", value: "Loading…", tone: "neutral" },
    ];
  }

  if (!health || errored) {
    return [
      { label: "Configured", value: "Unavailable", tone: "bad" },
      { label: "Reachable", value: "Unavailable", tone: "bad" },
      { label: "Network", value: "Unavailable", tone: "bad" },
      { label: "RLUSD", value: "Unavailable", tone: "bad" },
    ];
  }

  const badges: HealthBadge[] = [
    {
      label: "Configured",
      value: health.configured ? "Yes" : "No",
      tone: health.configured ? "good" : "bad",
    },
    {
      label: "Reachable",
      value: health.reachable ? "Yes" : "No",
      // Reachability only matters once configured; surface as warn when not
      // configured so it does not look like a hard failure.
      tone: health.reachable ? "good" : health.configured ? "bad" : "warn",
    },
    {
      label: "Network",
      value: health.network || "Unknown",
      tone: health.network ? "neutral" : "warn",
    },
    {
      label: "RLUSD",
      value: health.rlusd_configured ? "Configured" : "Not configured",
      tone: health.rlusd_configured ? "good" : "warn",
    },
  ];

  // Demo wallet badge is only rendered if the backend reports it as still
  // configured — surface it as a warning so operators notice it's present.
  if (health.demo_wallet_configured) {
    badges.push({
      label: "Demo wallet",
      value: "Configured",
      tone: "warn",
    });
  }

  if (health.signing_enabled !== undefined) {
    badges.push({
      label: "Signing",
      value: health.signing_enabled ? "Enabled" : "Disabled",
      tone: health.signing_enabled ? "good" : "warn",
    });
  }

  if (health.signing_mode !== undefined) {
    const mode = health.signing_mode ? health.signing_mode : "unknown";
    badges.push({
      label: "Signing mode",
      value: mode,
      tone: mode === "disabled" || mode === "unknown" ? "warn" : "neutral",
    });
  }

  if (health.signer_configured !== undefined) {
    badges.push({
      label: "Signer",
      value: health.signer_configured ? "Configured" : "Not configured",
      tone: health.signer_configured ? "good" : "warn",
    });
  }

  return badges;
}

/**
 * XRPLHealthPanel
 *
 * Renders the XRPL network health bar previously inlined in App.tsx as
 * `adapterBar`. Owns its own fetch lifecycle (loading / data / error) so
 * the page-level orchestrator does not need to manage health state.
 */
export default function XRPLHealthPanel() {
  const [health, setHealth] = useState<XRPLHealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [errored, setErrored] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setErrored(false);
    apiGet<XRPLHealthResponse>("/v1/xrpl/health")
      .then((d) => {
        if (cancelled) return;
        setHealth(d);
        setErrored(false);
      })
      .catch((err) => {
        console.error("Failed to fetch XRPL health:", err);
        if (cancelled) return;
        setHealth(null);
        setErrored(true);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const badges = buildXrplHealthBadges(health, loading, errored);

  return (
    <div className="adapterBar" data-testid="xrpl-health-panel">
      <span className="adapterBarLabel">XRPL Network</span>
      {badges.map((badge) => (
        <span
          key={badge.label}
          className={`badge ${badge.tone}`}
          title={badge.label}
          data-testid="xrpl-health-badge"
          data-badge-label={badge.label}
        >
          <span className="badgeDot" />
          <span className="badgeLabel">{badge.label}:</span>
          <span className="badgeValue">{badge.value}</span>
        </span>
      ))}
    </div>
  );
}
