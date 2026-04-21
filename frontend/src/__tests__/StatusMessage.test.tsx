import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import StatusMessage from "../components/StatusMessage";

/**
 * Smoke test for the shared `StatusMessage` primitive.
 *
 * Intentionally minimal: this exists to validate the Vitest + React Testing
 * Library scaffold (jsdom env, jest-dom matchers, the `data-testid` hook on
 * the rendered root). Future UI integration tests can follow this pattern
 * — render a component, query by `data-testid`, assert on accessible
 * attributes / text — without having to re-bootstrap the toolchain.
 */
describe("StatusMessage", () => {
  it("renders the default title and body for a given variant", () => {
    render(
      <StatusMessage variant="error">Something went wrong.</StatusMessage>,
    );

    const node = screen.getByTestId("status-message");
    expect(node).toBeInTheDocument();
    expect(node).toHaveAttribute("data-variant", "error");
    expect(node).toHaveAttribute("role", "alert");
    expect(node).toHaveTextContent("Error");
    expect(node).toHaveTextContent("Something went wrong.");
  });

  it("marks loading state as busy for assistive tech", () => {
    render(<StatusMessage variant="loading" title="Fetching…" />);

    const node = screen.getByTestId("status-message");
    expect(node).toHaveAttribute("data-variant", "loading");
    expect(node).toHaveAttribute("aria-busy", "true");
    expect(node).toHaveTextContent("Fetching…");
  });
});
