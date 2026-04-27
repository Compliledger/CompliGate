import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * Tests for `getXrplExplorerUrl`.
 *
 * The helper reads the explorer base URL via the `../config` module, so each
 * test resets module state and re-mocks `../config` to simulate a different
 * `VITE_XRPL_EXPLORER_BASE_URL` deployment value.
 */
afterEach(() => {
  vi.resetModules();
  vi.doUnmock("../config");
});

async function loadHelper(baseUrl: string) {
  vi.doMock("../config", () => ({ XRPL_EXPLORER_BASE_URL: baseUrl }));
  const mod = await import("../lib/xrplExplorer");
  return mod.getXrplExplorerUrl;
}

describe("getXrplExplorerUrl", () => {
  it("returns null when no explorer base URL is configured", async () => {
    const getXrplExplorerUrl = await loadHelper("");
    expect(
      getXrplExplorerUrl("ABCDEF0123456789", "testnet"),
    ).toBeNull();
  });

  it("returns null for missing or blank tx_hash even when configured", async () => {
    const getXrplExplorerUrl = await loadHelper(
      "https://testnet.xrpl.org/transactions",
    );
    expect(getXrplExplorerUrl(undefined, "testnet")).toBeNull();
    expect(getXrplExplorerUrl(null, "testnet")).toBeNull();
    expect(getXrplExplorerUrl("", "testnet")).toBeNull();
    expect(getXrplExplorerUrl("   ", "testnet")).toBeNull();
  });

  it("appends the tx_hash to the configured base URL", async () => {
    const getXrplExplorerUrl = await loadHelper(
      "https://testnet.xrpl.org/transactions",
    );
    expect(getXrplExplorerUrl("ABCDEF0123456789", "testnet")).toBe(
      "https://testnet.xrpl.org/transactions/ABCDEF0123456789",
    );
  });

  it("trims whitespace and URL-encodes the tx_hash", async () => {
    const getXrplExplorerUrl = await loadHelper(
      "https://example.test/tx",
    );
    expect(getXrplExplorerUrl("  abc def  ", "testnet")).toBe(
      "https://example.test/tx/abc%20def",
    );
  });

  it("works without a network argument", async () => {
    const getXrplExplorerUrl = await loadHelper("https://example.test/tx");
    expect(getXrplExplorerUrl("DEADBEEF")).toBe(
      "https://example.test/tx/DEADBEEF",
    );
  });

  it("uses the configured base URL regardless of network so a mainnet explorer is never hardcoded for testnet", async () => {
    // No env var set -> no link, even for a mainnet-looking network value.
    const noExplorer = await loadHelper("");
    expect(noExplorer("ABCDEF", "mainnet")).toBeNull();
    expect(noExplorer("ABCDEF", "testnet")).toBeNull();
  });
});
