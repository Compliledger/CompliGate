import {
  formatCheckedAt,
  formatStatusLabel,
  outcomeClass,
  outcomeSymbol,
  outcomeTextClass,
  providerOutcome,
} from "../lib/format";
import type { PermitResponse } from "../types/api";

type Props = {
  /** Active permit; the source of provider attestations. */
  permit: PermitResponse | null;
  /** Optional override for the section header. */
  title?: string;
};

type ProviderRow = {
  /** Stable identifier used for keys / data attributes. */
  id: "sanctions" | "kyc" | "reserve";
  /** Operational label for the row (e.g. "Sanctions"). */
  label: string;
  /** Provider / source name, when known. */
  provider: string | null;
  /** Backend status string passed through `providerOutcome`. */
  status: string | null | undefined;
  /** Unix seconds timestamp the provider check was last performed. */
  checkedAt: number | null | undefined;
  /**
   * Raw evidence reference returned by the provider (e.g.
   * `mock:rAddr:2024-01-01T00:00:00+00:00` for the mock sanctions
   * provider). Surfaced verbatim so operators can audit it.
   */
  evidenceReference?: string | null;
};

/**
 * Map the cross-cutting `ProviderStatus` vocabulary onto the raw
 * provider-decision label requested by the operator surface
 * (`PASS` / `DENY` / `UNAVAILABLE`). The mock sanctions provider's
 * notice block lists the underlying decision verbatim so the UI does
 * not paper over a non-pass outcome with a friendlier-looking word.
 */
function rawDecisionLabel(status: string | null | undefined): string {
  switch (status) {
    case "approved":
    case "verified":
    case "passed":
      return "PASS";
    case "denied":
    case "not_verified":
      return "DENY";
    case "unavailable":
      return "UNAVAILABLE";
    default:
      return "NOT EVALUATED";
  }
}

/**
 * Returns true when the provider id identifies a mock / simulated
 * provider rather than a real upstream integration. Mock providers
 * (currently `mock_trm` for sanctions) must be flagged in the UI so
 * operators never mistake their output for real compliance evidence.
 */
function isMockProviderId(providerId: string | null | undefined): boolean {
  return typeof providerId === "string" && providerId.startsWith("mock_");
}

/**
 * Build the three provider rows (sanctions, KYC, reserve / liquidity)
 * from the active permit. Each row pulls the provider name and
 * `checked_at` timestamp from the most authoritative source available
 * — the normalized attestation result when present, otherwise the
 * per-check entry in `bundle.compliance_evidence` — without
 * fabricating data the backend did not actually return.
 */
function buildRows(permit: PermitResponse): ProviderRow[] {
  const evidence = permit.bundle.compliance_evidence ?? [];
  const sanctionsItem = evidence.find((e) => e.check === "sanctions");
  const kycItem = evidence.find((e) => e.check === "kyc");
  const reserveItem = evidence.find((e) => e.check === "reserve");
  const liquidityItem = evidence.find((e) => e.check === "liquidity");

  const kycResult = permit.bundle.attestations.kyc_result;
  const reserveResult = permit.bundle.attestations.reserve_result;
  // `summary` is required by the type, but the runtime payload can be
  // missing when the backend issues a fail-closed denial without a
  // populated summary. Treat any missing field as `not_evaluated` (via
  // `providerOutcome`'s null handling) rather than crashing — and never
  // as a passing outcome.
  const summary = permit.summary as PermitResponse["summary"] | undefined;

  return [
    {
      id: "sanctions",
      label: "Sanctions",
      provider: sanctionsItem?.provider_id ?? null,
      status: summary?.sanctions_status ?? null,
      checkedAt: sanctionsItem?.checked_at ?? null,
      evidenceReference:
        sanctionsItem?.reference ??
        permit.bundle.attestations.sanctions_reference ??
        null,
    },
    {
      id: "kyc",
      label: "KYC",
      provider: kycResult?.provider_name ?? kycItem?.provider_id ?? null,
      status: summary?.kyc_status ?? null,
      checkedAt: kycResult?.checked_at ?? kycItem?.checked_at ?? null,
    },
    {
      id: "reserve",
      label: "Reserve / Liquidity",
      provider:
        reserveResult?.provider_name ??
        reserveItem?.provider_id ??
        liquidityItem?.provider_id ??
        null,
      // Use the reserve status as the row's primary status; the
      // liquidity status is captured separately in the dedicated
      // permit summary panel. Falling back to liquidity_status here
      // keeps the row informative when a deployment only attests
      // liquidity (e.g. exchange venue) without a separate reserve
      // attestation.
      status:
        summary?.reserve_status ?? summary?.liquidity_status ?? null,
      checkedAt:
        reserveResult?.checked_at ??
        reserveItem?.checked_at ??
        liquidityItem?.checked_at ??
        null,
    },
  ];
}

/**
 * ProviderStatusSummary
 *
 * Compact, operationally-styled overview of the three cross-cutting
 * compliance providers that back a permit: sanctions screening, KYC,
 * and reserve / liquidity attestation. Each row surfaces the provider
 * name, the normalized status, and the last-checked timestamp (when
 * available).
 *
 * Intended to sit at the bottom of permit / settlement verification
 * results so an operator can see, at a glance, *which* upstream
 * sources stood behind the result they are looking at — without
 * scrolling back to the full constraints snapshot or technical proof
 * sections.
 */
export default function ProviderStatusSummary({
  permit,
  title = "Provider Status",
}: Props) {
  if (!permit) return null;
  const rows = buildRows(permit);

  return (
    <div
      className="providerStatusSummary"
      data-testid="provider-status-summary"
    >
      <div className="providerStatusHeader">{title}</div>
      <div className="providerStatusList">
        {rows.map((row) => {
          const outcome = providerOutcome(row.status);
          const checkedAtLabel = formatCheckedAt(row.checkedAt);
          const isMock = row.id === "sanctions" && isMockProviderId(row.provider);
          const mockIsWarn = isMock && outcome !== "verified";
          return (
            <div
              key={row.id}
              className="providerStatusRow"
              data-testid={`provider-status-row-${row.id}`}
            >
              <span className={outcomeClass(outcome)}>
                {outcomeSymbol(outcome)}
              </span>
              <div className="providerStatusMain">
                <div className="providerStatusLabelLine">
                  <span className="providerStatusLabel">{row.label}</span>
                  <span className="providerStatusProvider">
                    {row.provider ?? (
                      <span className="textMuted">No provider configured</span>
                    )}
                  </span>
                </div>
                {checkedAtLabel && (
                  <div className="providerStatusMeta">
                    <span className="providerStatusMetaLabel">
                      Last checked
                    </span>
                    {checkedAtLabel}
                  </div>
                )}
                {isMock && (
                  <div
                    className={
                      mockIsWarn
                        ? "providerStatusMockNotice providerStatusMockNotice--warn"
                        : "providerStatusMockNotice"
                    }
                    data-testid="provider-status-mock-notice"
                    role={mockIsWarn ? "alert" : undefined}
                  >
                    <div className="providerStatusMockBadge">
                      Mock provider (TRM integration pending)
                    </div>
                    <div className="providerStatusMockMeta">
                      <span className="providerStatusMetaLabel">Provider</span>
                      <span data-testid="provider-status-mock-provider">
                        {row.provider}
                      </span>
                    </div>
                    <div className="providerStatusMockMeta">
                      <span className="providerStatusMetaLabel">Status</span>
                      <span data-testid="provider-status-mock-decision">
                        {rawDecisionLabel(row.status)}
                      </span>
                    </div>
                    <div className="providerStatusMockMeta">
                      <span className="providerStatusMetaLabel">Evidence</span>
                      <span data-testid="provider-status-mock-evidence">
                        {row.evidenceReference ?? (
                          <span className="textMuted">none</span>
                        )}
                      </span>
                    </div>
                    <div className="providerStatusMockDisclaimer">
                      Simulated screening only — not real compliance.
                    </div>
                  </div>
                )}
              </div>
              <span
                className={`providerStatusValue ${outcomeTextClass(outcome)}`}
              >
                {formatStatusLabel(row.status)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
