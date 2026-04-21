/// <reference types="vitest" />
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

/**
 * Vitest configuration for the CompliGate frontend.
 *
 * Kept intentionally lightweight: jsdom environment, a shared setup file
 * that wires `@testing-library/jest-dom` matchers, and a glob that picks
 * up tests colocated under `src/` (e.g. `src/__tests__/**` or
 * `*.test.ts(x)` next to the file under test).
 */
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    css: false,
  },
});
