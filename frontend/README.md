# CompliGate Frontend

React + TypeScript + Vite UI for the CompliGate compliance authorization
backend. The frontend is a thin client over the productionized FastAPI
backend: it requests time-bound compliance permits, verifies signed permit
bundles, checks XRPL trustlines, and verifies settled XRPL transactions
against a permit's bundle hash.

## Requirements

- Node.js 18+ (Vite 6 requires Node ≥ 18.18)
- A running CompliGate backend (see `../backend/README.md`)

## Setup

```bash
npm install
cp .env.example .env
# edit .env to point at your backend and (optionally) ship a default API key
```

### Environment variables

| Variable        | Purpose                                                                                                  |
| --------------- | -------------------------------------------------------------------------------------------------------- |
| `VITE_API_BASE` | Base URL of the CompliGate backend (no trailing slash). Default `http://localhost:8000`.                 |
| `VITE_API_KEY`  | Optional build-time default for the `X-API-Key` header. Users can override at runtime in the UI.         |

The CORS allow-list on the backend (`CORS_ORIGINS` env) must include the
origin where this app is served (e.g. `http://localhost:5173` for `vite dev`).

## Scripts

| Command         | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| `npm run dev`   | Start the Vite dev server on `http://localhost:5173`.        |
| `npm run lint`  | Type-check the project (`tsc --noEmit`).                     |
| `npm run build` | Type-check and produce a production bundle in `dist/`.       |
| `npm run preview` | Serve the production bundle locally for smoke testing.     |
| `npm test`      | Run the UI test suite once (Vitest + React Testing Library). See [`src/__tests__/README.md`](src/__tests__/README.md). |
| `npm run test:watch` | Re-run tests on file changes during local development. |

## API key handling

All backend endpoints other than `/v1/xrpl/health` require an API key
(`X-API-Key` header, or `Authorization: Bearer …`). The frontend resolves
the key in this order:

1. The value the user enters via the **Set API Key** panel at the top of the
   page (stored in `localStorage` under `compligate.apiKey`, browser-only).
2. The build-time `VITE_API_KEY` value from `.env`.

If no key is configured the UI still loads, but authenticated calls will
surface a clear `Unauthorized — check that your API key is set and valid.`
error.

All HTTP traffic flows through `src/lib/api.ts` (`apiFetch`, plus the
`apiGet` / `apiPost` helpers), which centralizes the base URL, request
timeout, JSON handling, key injection and structured error reporting.

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
- Make sure the backend's `CORS_ORIGINS` includes the deployed origin.

## Demo flow (preserved)

1. **Request Permit** — issue a signed, time-bound permit for a subject.
2. **Check Trustline** — confirm an XRPL account holds the expected
   trustline for the configured RLUSD issuer/currency.
3. **Provide Settled XRPL Transaction Hash** — paste a tx hash that was
   settled from your own wallet.
4. **Verify Settlement** — verify the settled transaction against the
   permit's bundle hash and constraints (renders the persisted proof
   artifact returned by the backend).
5. **View Proof Artifact** — verify the permit signature and inspect the
   bundle, signature, regulatory controls and proof artifact.

Supplemental cards: **Permit Constraints Snapshot** and **Transaction
Lookup** (look up any XRPL tx by hash and reuse it for verification).
