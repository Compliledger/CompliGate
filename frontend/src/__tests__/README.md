# Frontend UI Tests

Lightweight scaffold for future UI integration tests. The toolchain piggy-backs
on the existing Vite + TypeScript stack so no new build pipeline is introduced.

## Stack

- **Test runner**: [Vitest](https://vitest.dev/) (uses the project's existing
  Vite config and TS settings).
- **DOM environment**: `jsdom`.
- **Component rendering / queries**: `@testing-library/react` and
  `@testing-library/jest-dom` matchers.

Configuration lives in `frontend/vitest.config.ts` and the shared setup file
(`src/test/setup.ts`) registers the jest-dom matchers and an automatic DOM
cleanup between tests.

## Scripts

From `frontend/`:

| Command              | Description                                  |
| -------------------- | -------------------------------------------- |
| `npm test`           | Run the test suite once (CI-friendly).       |
| `npm run test:watch` | Re-run tests on file changes (local dev).    |

## Conventions

- **Location**: tests live either next to the file under test as
  `<Component>.test.tsx`, or under `src/__tests__/`. Both are picked up by
  the `src/**/*.{test,spec}.{ts,tsx}` glob in `vitest.config.ts`.
- **Selectors**: prefer `getByRole` / `getByLabelText` first, then fall back
  to `getByTestId`. Components expose stable `data-testid` hooks for
  high-traffic elements (panel roots, form inputs, primary action buttons,
  status messages, result containers). Do **not** rely on copy or styling
  for selection — both are likely to change.
- **API calls**: components route every backend call through
  `src/lib/api.ts` (`apiGet` / `apiPost`). Tests should mock that module
  (e.g. `vi.mock("../lib/api", ...)`) rather than stubbing `fetch` directly.
  This keeps tests decoupled from the API key / header / timeout plumbing.
- **Inline logic**: keep tests focused on observable behaviour (rendered
  output, accessibility attributes, callbacks invoked). Avoid asserting on
  internal React state.

## Current coverage

This change introduces a single smoke test (`StatusMessage.test.tsx`) to
validate the scaffold. It is intentionally not a full suite — additional
panel-level tests can be added incrementally using the same pattern.
