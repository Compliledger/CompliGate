import type { ReactNode } from "react";

/**
 * StatusMessage
 *
 * Single, shared visual primitive used by every panel to render the five
 * canonical states:
 *
 *   - empty   — no data has been produced yet
 *   - loading — an async request is in flight
 *   - success — backend returned a positive outcome
 *   - warning — backend returned a non-fatal condition that needs attention
 *   - error   — backend (or client validation) returned a failure
 *
 * Keeping these in one component (and one set of CSS classes) is what
 * makes empty / error / loading look the same everywhere in the app.
 *
 * The component intentionally has no behavior — it does not re-fetch,
 * retry, or alter any product flow. It is purely presentational.
 */

export type StatusVariant =
  | "empty"
  | "loading"
  | "success"
  | "warning"
  | "error";

type Props = {
  variant: StatusVariant;
  /** Short label rendered in bold (e.g. "No data yet", "Error"). Optional. */
  title?: ReactNode;
  /** Body content, typically the human-readable message. */
  children?: ReactNode;
  /** Extra class for layout tweaks (e.g. compact spacing). */
  className?: string;
  /**
   * If true, render with no top margin. Useful when the message is the
   * first child of a result area.
   */
  compact?: boolean;
};

const ICONS: Record<StatusVariant, string> = {
  empty: "—",
  loading: "",
  success: "✔",
  warning: "!",
  error: "✘",
};

const DEFAULT_TITLES: Record<StatusVariant, string> = {
  empty: "No data yet",
  loading: "Loading…",
  success: "Success",
  warning: "Warning",
  error: "Error",
};

export default function StatusMessage({
  variant,
  title,
  children,
  className,
  compact,
}: Props) {
  const classes = [
    "statusMessage",
    `statusMessage--${variant}`,
    compact ? "statusMessage--compact" : "",
    className ?? "",
  ]
    .filter(Boolean)
    .join(" ");

  const resolvedTitle = title ?? DEFAULT_TITLES[variant];

  return (
    <div
      className={classes}
      role={variant === "error" ? "alert" : "status"}
      aria-live={variant === "loading" ? "polite" : undefined}
      aria-busy={variant === "loading" ? true : undefined}
    >
      <span className="statusMessageIcon" aria-hidden="true">
        {variant === "loading" ? <span className="statusMessageSpinner" /> : ICONS[variant]}
      </span>
      <div className="statusMessageBody">
        {resolvedTitle && <div className="statusMessageTitle">{resolvedTitle}</div>}
        {children && <div className="statusMessageText">{children}</div>}
      </div>
    </div>
  );
}
