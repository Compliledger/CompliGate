# CompliGate Frontend

React + TypeScript + Vite UI for the CompliGate compliance authorization
backend. The frontend is a thin client over the productionized FastAPI
backend: it requests time-bound compliance permits, verifies signed permit
bundles, checks XRPL trustlines, and verifies settled XRPL transactions
against a permit's bundle hash.

## Requirements

- Node.js 18+ (Vite 6 requires Node ≥ 18.18)
- A running CompliGate backend (see `../backend/README.md`)

## Environment variables

| Variable              | Purpose                                                                                                  |
| --------------------- | -------------------------------------------------------------------------------------------------------- |
| `VITE_API_BASE`       | Base URL of the CompliGate backend (no trailing slash). Defaults to `http://localhost:8000`.             |
| `VITE_API_KEY`        | Optional build-time default for the API key header. Users can override at runtime in the UI.             |
| `VITE_API_KEY_HEADER` | Optional header name for the API key. Defaults to `X-API-Key`; must match the backend setting.           |

`VITE_*` values are inlined at build time, so any change requires
re-running `npm run dev` or `npm run build`.

| Command         | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| `npm run dev`   | Start the Vite dev server on `http://localhost:5173`.        |
| `npm run lint`  | Type-check the project (`tsc --noEmit`).                     |
| `npm run build` | Type-check and produce a production bundle in `dist/`.       |
| `npm run preview` | Serve the production bundle locally for smoke testing.     |
| `npm test`      | Run the UI test suite once (Vitest + React Testing Library). See [`src/__tests__/README.md`](src/__tests__/README.md). |
| `npm run test:watch` | Re-run tests on file changes during local development. |
The CORS allow-list on the backend (`CORS_ORIGINS`) must include the
origin where this app is served (e.g. `http://localhost:5173` for
`vite dev`).

## Local startup

```bash
npm install
cp .env.example .env   # set VITE_API_BASE / VITE_API_KEY as needed
npm run dev            # http://localhost:5173
```

Other scripts:

| Command           | Description                                            |
| ----------------- | ------------------------------------------------------ |
| `npm run lint`    | Type-check the project (`tsc --noEmit`).               |
| `npm run build`   | Type-check and produce a production bundle in `dist/`. |
| `npm run preview` | Serve the production bundle locally for smoke testing. |

## Production build

```bash
npm run build
```

The output in `dist/` is a static bundle that can be served by any static
host (Netlify, Vercel, S3 + CloudFront, Nginx, etc.). It only needs to be
able to reach `VITE_API_BASE` over HTTPS.

When deploying:

- Set `VITE_API_BASE` to the public backend URL **before** running
  `npm run build` (Vite inlines `VITE_*` vars at build time).
- Decide whether to ship `VITE_API_KEY` in the build (convenient for
  internal demos) or require operators to paste a key into the UI
  (recommended for shared deployments — keys never leave the browser).
- Ensure the backend's `CORS_ORIGINS` includes the deployed origin.

## How the frontend talks to the backend

The frontend is a pure client of the FastAPI backend — it holds no
business state of its own. All HTTP traffic flows through a single
client in `src/lib/api.ts` (`apiFetch`, with `apiGet` / `apiPost`
helpers), which:

- prefixes every request with `VITE_API_BASE`;
- injects the configured API key header on every request;
- applies a default request timeout (15s);
- parses JSON responses and normalizes failures into typed
  `ApiError` / `ApiTimeoutError` / `ApiNetworkError` objects with
  human-readable messages.

Build-time configuration is centralized in `src/config.ts`; feature
components never read `import.meta.env.*` directly.

## Protected endpoints

All backend endpoints other than `/v1/xrpl/health` require an API key,
sent in the `X-API-Key` header (or whatever `VITE_API_KEY_HEADER` is
set to). The frontend resolves the active key in this order:

1. A key entered via the **Set API Key** panel at the top of the page,
   persisted in `localStorage` under `compligate.apiKey` (browser-only,
   never sent anywhere except as the API-key header to the backend).
2. The build-time `VITE_API_KEY` value from `.env`.

If no key is configured the UI still loads, but authenticated calls
surface a clear `Unauthorized — check that your API key is set and
valid.` error. A `403` is reported as `Forbidden — this API key is not
allowed to perform this action.`

## Demo flow

The UI walks through the end-to-end compliance + settlement loop:

1. **Request Permit** — issue a signed, time-bound permit for a subject;
   the backend returns the bundle, signature and bundle hash.
2. **Trustline Check** — confirm the XRPL account holds the expected
   trustline for the configured RLUSD issuer/currency.
3. **XRPL Payment** — submit (or paste) the hash of a settled XRPL
   payment made from your own wallet that satisfies the permit.
4. **Settlement Verification** — verify the settled transaction against
   the permit's bundle hash and regulatory constraints.
5. **Proof Artifact** — verify the permit signature and inspect the
   persisted proof artifact (bundle, signature, controls, settlement
   evidence) returned by the backend.

Supplemental cards: **Permit Constraints Snapshot** and **Transaction
Lookup** (look up any XRPL tx by hash and reuse it for verification).
