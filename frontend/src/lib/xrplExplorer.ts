/**
 * Helpers for deep-linking an XRPL transaction hash to a configured
 * block explorer.
 *
 * The frontend never hardcodes a public XRPL explorer (e.g. a mainnet
 * "livenet" URL), because doing so would silently resolve testnet /
 * devnet transactions against the wrong network — making it look like a
 * compliance-bound payment never happened, or pointing reviewers at an
 * unrelated mainnet transaction with a coincidentally similar id.
 *
 * Instead, operators configure `VITE_XRPL_EXPLORER_BASE_URL` to match
 * the network the backend is actually submitting to (testnet, devnet,
 * a self-hosted explorer, etc.). When the env var is unset, the UI
 * simply renders the raw `tx_hash` with no link.
 */
import { XRPL_EXPLORER_BASE_URL } from "../config";

/**
 * Build an explorer URL for the given XRPL transaction hash, or
 * return `null` when no explorer base URL has been configured.
 *
 * @param txHash  The XRPL transaction hash returned by the backend.
 * @param network Optional XRPL network identifier reported by the
 *                backend (e.g. `"testnet"`, `"devnet"`, `"mainnet"`).
 *                Currently informational only — the configured base
 *                URL is the single source of truth for which network
 *                the link points at, so a misconfigured deployment can
 *                never silently fall back to a mainnet explorer for a
 *                testnet transaction.
 *
 * @returns The full explorer URL, or `null` when:
 *           - `VITE_XRPL_EXPLORER_BASE_URL` is not set, or
 *           - `txHash` is missing / blank.
 */
export function getXrplExplorerUrl(
  txHash: string | null | undefined,
  _network?: string | null | undefined,
): string | null {
  const base = XRPL_EXPLORER_BASE_URL;
  if (!base) return null;
  if (typeof txHash !== "string") return null;
  const trimmed = txHash.trim();
  if (!trimmed) return null;
  // Base already has trailing slashes stripped in `config.ts`.
  return `${base}/${encodeURIComponent(trimmed)}`;
}
