/**
 * Renders the small numbered badge used in panel headers (e.g. "1", "2"...).
 *
 * Extracted from App.tsx so each panel component can render its own badge
 * without redefining the helper locally.
 */
export default function PanelNumber({ n }: { n: number }) {
  return <span className="panelNumber">{n}</span>;
}
