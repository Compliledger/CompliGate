#!/usr/bin/env node
// CompliGate — live endpoint test suite
// Usage:
//   node test-live.js
//   BASE_URL=https://... API_KEY=... node test-live.js

const BASE_URL = process.env.BASE_URL || "https://compligate-backend-production.up.railway.app";
const API_KEY  = process.env.API_KEY  || "XE9pPPClF_Qun9tojqHh9XzeNxRgmY1fD7yPEvJs0Rs";
const API_KEY_HEADER = "X-API-Key";

// ── colours ──────────────────────────────────────────────────────────────────
const c = {
  reset:  "\x1b[0m",
  bold:   "\x1b[1m",
  green:  "\x1b[32m",
  red:    "\x1b[31m",
  yellow: "\x1b[33m",
  cyan:   "\x1b[36m",
  grey:   "\x1b[90m",
};

const REQUEST_TIMEOUT_MS = 15000;
const ROUNDTRIP_TIMEOUT_MS = 60000; // submit_and_wait can take ~15-30 s
const ROUNDTRIP_DESTINATION = process.env.ROUNDTRIP_DESTINATION || "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";

// ── tiny HTTP helpers ─────────────────────────────────────────────────────────
async function request(method, path, body, auth = true) {
  const headers = { "Content-Type": "application/json" };
  if (auth) headers[API_KEY_HEADER] = API_KEY;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
    let json = null;
    try { json = await res.json(); } catch (_) {}
    return { status: res.status, ok: res.ok, json };
  } catch (err) {
    if (err.name === "AbortError") return { status: 0, ok: false, json: null, timedOut: true };
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

const GET  = (path, auth = true)       => request("GET",  path, null, auth);
const POST = (path, body, auth = true) => request("POST", path, body, auth);

async function postWithTimeout(path, body, timeoutMs) {
  const headers = { "Content-Type": "application/json", [API_KEY_HEADER]: API_KEY };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    let json = null;
    try { json = await res.json(); } catch (_) {}
    return { status: res.status, ok: res.ok, json };
  } catch (err) {
    if (err.name === "AbortError") return { status: 0, ok: false, json: null, timedOut: true };
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

// ── test runner ───────────────────────────────────────────────────────────────
let passed = 0, failed = 0, skipped = 0;
const failures = [];

function pass(name) {
  passed++;
  console.log(`  ${c.green}✓${c.reset} ${name}`);
}

function fail(name, reason) {
  failed++;
  failures.push({ name, reason });
  console.log(`  ${c.red}✗${c.reset} ${c.bold}${name}${c.reset}`);
  console.log(`    ${c.red}${reason}${c.reset}`);
}

function skip(name, reason) {
  skipped++;
  console.log(`  ${c.yellow}~${c.reset} ${c.grey}${name} — ${reason}${c.reset}`);
}

function section(title) {
  console.log(`\n${c.cyan}${c.bold}── ${title} ──────────────────────────────${c.reset}`);
}

function assert(cond, name, reason) {
  cond ? pass(name) : fail(name, reason);
  return cond;
}

// ── shared state (flows depend on prior results) ──────────────────────────────
let permitBundle   = null;
let permitSig      = null;
let permitBundleHash = null;

// ═════════════════════════════════════════════════════════════════════════════
async function run() {
  console.log(`\n${c.bold}CompliGate Live Test Suite${c.reset}`);
  console.log(`${c.grey}Target: ${BASE_URL}${c.reset}\n`);

  // ── 1. Public endpoints (no auth) ─────────────────────────────────────────
  section("1 · Public endpoints");

  {
    const r = await GET("/health", false);
    assert(r.status === 200,         "GET /health → 200",           `got ${r.status}`);
    assert(r.json?.status === "ok",  "GET /health body.status=ok",  `got ${JSON.stringify(r.json)}`);
  }

  {
    const r = await GET("/public-key", false);
    assert(r.status === 200,              "GET /public-key → 200",        `got ${r.status}`);
    const hasKey = typeof r.json?.public_key === "string" || typeof r.json?.public_key_b64 === "string" || typeof r.json?.public_key_hex === "string";
    assert(hasKey, "GET /public-key has a public key field", `got ${JSON.stringify(r.json)}`);
  }

  {
    const r = await GET("/v1/xrpl/health", false);
    assert(r.status === 200, "GET /v1/xrpl/health → 200", `got ${r.status}`);
    const hasStatus = "connected" in (r.json ?? {}) || "reachable" in (r.json ?? {}) || "configured" in (r.json ?? {});
    assert(hasStatus, "GET /v1/xrpl/health has status field", `got ${JSON.stringify(r.json)}`);
  }

  // ── 2. Auth rejection ─────────────────────────────────────────────────────
  section("2 · Auth rejection");

  {
    const r = await POST("/v1/permit", { subject: "test" }, false);
    assert(r.status === 401 || r.status === 403, "POST /v1/permit without key → 401/403", `got ${r.status}`);
  }

  {
    const r = await request("POST", "/v1/permit", { subject: "test" }, false);
    const headers2 = { "Content-Type": "application/json", [API_KEY_HEADER]: "wrong-key-abc" };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    let wrongKeyStatus = 0;
    try {
      const res2 = await fetch(`${BASE_URL}/v1/permit`, {
        method: "POST",
        headers: headers2,
        body: JSON.stringify({ subject: "test" }),
        signal: controller.signal,
      });
      wrongKeyStatus = res2.status;
    } catch (err) {
      if (err.name !== "AbortError") throw err;
      wrongKeyStatus = 0;
    } finally {
      clearTimeout(timer);
    }
    assert(wrongKeyStatus === 401 || wrongKeyStatus === 403, "POST /v1/permit with wrong key → 401/403", `got ${wrongKeyStatus}`);
  }

  // ── 3. Permit issuance ────────────────────────────────────────────────────
  section("3 · Permit issuance");

  {
    const r = await POST("/v1/permit", {
      subject: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
      action: "transfer",
      amount: 100,
    });

    const ok = assert(r.status === 200, "POST /v1/permit → 200", `got ${r.status} — ${JSON.stringify(r.json)}`);
    if (ok) {
      assert(typeof r.json?.bundle_hash === "string",   "permit has bundle_hash",     `got ${JSON.stringify(r.json?.bundle_hash)}`);
      assert(typeof r.json?.signature === "string",     "permit has signature",        `got ${typeof r.json?.signature}`);
      assert(typeof r.json?.bundle === "object",        "permit has bundle object",    `got ${typeof r.json?.bundle}`);
      assert(typeof r.json?.expires_at === "number",    "permit has expires_at",       `got ${typeof r.json?.expires_at}`);
      assert(typeof r.json?.decision_result === "string", "permit has decision_result", `got ${r.json?.decision_result}`);
      assert(Array.isArray(r.json?.reason_codes),       "permit has reason_codes[]",   `got ${typeof r.json?.reason_codes}`);
      assert(typeof r.json?.proof_artifact === "object","permit has proof_artifact",   `got ${typeof r.json?.proof_artifact}`);

      permitBundle     = r.json.bundle;
      permitSig        = r.json.signature;
      permitBundleHash = r.json.bundle_hash;
    }
  }

  // trustset action
  {
    const r = await POST("/v1/permit", {
      subject: "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
      action: "trustset",
    });
    assert(r.status === 200, "POST /v1/permit (trustset action) → 200", `got ${r.status}`);
    assert(r.json?.bundle?.action === "trustset", "permit bundle.action=trustset", `got ${r.json?.bundle?.action}`);
  }

  // ── 4. Proof artifact endpoint ────────────────────────────────────────────
  section("4 · Proof artifact");

  {
    const r = await POST("/v1/proof-artifact", {
      subject: "rN7n3473SaZBCG4dFL75S9YMgCGZBEBN9B",
      action: "transfer",
      amount: 50,
    });
    assert(r.status === 200,                         "POST /v1/proof-artifact → 200",              `got ${r.status}`);
    assert(typeof r.json?.bundle_hash === "string",  "proof-artifact has bundle_hash",              `got ${typeof r.json?.bundle_hash}`);
    assert(typeof r.json?.decision_result === "string", "proof-artifact has decision_result",       `got ${r.json?.decision_result}`);
  }

  // ── 5. Permit verification ────────────────────────────────────────────────
  section("5 · Permit verification");

  if (!permitBundle || !permitSig) {
    skip("POST /v1/verify (valid bundle)", "permit issuance failed, cannot verify");
    skip("POST /v1/verify (tampered sig)", "permit issuance failed, cannot verify");
  } else {
    {
      const r = await POST("/v1/verify", { bundle: permitBundle, signature: permitSig });
      assert(r.status === 200,                           "POST /v1/verify (valid bundle) → 200",     `got ${r.status} — ${JSON.stringify(r.json)}`);
      const hasValidField = "valid" in (r.json ?? {}) || "permit_valid" in (r.json ?? {}) || "signature_valid" in (r.json ?? {});
      assert(hasValidField, "POST /v1/verify returns a validity field", `got ${JSON.stringify(r.json)}`);
    }

    {
      const r = await POST("/v1/verify", { bundle: permitBundle, signature: "aW52YWxpZHNpZw==" });
      assert(r.status === 200 || r.status === 400, "POST /v1/verify (tampered sig) → 200 or 400 with result", `got ${r.status}`);
    }
  }

  // ── 6. Settlement verify (full bundle path) ───────────────────────────────
  section("6 · Settlement verify — full bundle path");

  if (!permitBundle || !permitSig) {
    skip("POST /v1/settle/verify", "permit issuance failed, cannot test settlement");
  } else {
    // fake tx_hash — XRPL lookup will fail but API should still respond
    const r = await POST("/v1/settle/verify", {
      bundle: permitBundle,
      signature: permitSig,
      tx_hash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    // 400 = invalid permit or XRPL lookup failed gracefully — both are valid
    assert(
      r.status === 200 || r.status === 400 || r.status === 422,
      "POST /v1/settle/verify (fake tx) → structured response",
      `got ${r.status} — ${JSON.stringify(r.json)}`
    );
  }

  // invalid signature case
  {
    const r = await POST("/v1/settle/verify", {
      bundle: { sub: "x", exp: 9999999999 },
      signature: "aW52YWxpZA==",
      tx_hash: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    });
    assert(r.status === 400, "POST /v1/settle/verify (invalid sig) → 400", `got ${r.status}`);
  }

  // ── 7. Settlement verify by hash ──────────────────────────────────────────
  section("7 · Settlement verify — by bundle_hash");

  {
    const r = await POST("/v1/settlement/verify", {
      bundle_hash: "nonexistent-hash-000",
      tx_hash: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    });
    // 404 = no permit context found for that hash — expected behaviour
    assert(
      r.status === 200 || r.status === 404 || r.status === 400,
      "POST /v1/settlement/verify (unknown hash) → structured response",
      `got ${r.status}`
    );
  }

  if (permitBundleHash) {
    const r = await POST("/v1/settlement/verify", {
      bundle_hash: permitBundleHash,
      tx_hash: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
    });
    assert(
      r.status === 200 || r.status === 404 || r.status === 400,
      "POST /v1/settlement/verify (real bundle_hash, fake tx) → structured response",
      `got ${r.status} — ${JSON.stringify(r.json)}`
    );
  } else {
    skip("POST /v1/settlement/verify (real hash)", "permit issuance failed");
  }

  // ── 8. XRPL endpoints ─────────────────────────────────────────────────────
  section("8 · XRPL endpoints");

  {
    const r = await GET("/v1/xrpl/tx/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert(
      r.status === 200 || r.status === 404 || r.status === 400,
      "GET /v1/xrpl/tx/:hash (fake hash) → structured response",
      `got ${r.status}`
    );
  }

  {
    const r = await GET("/v1/xrpl/account/rTestAddress123/trustlines");
    assert(
      r.status === 200 || r.status === 404 || r.status === 400,
      "GET /v1/xrpl/account/:address/trustlines → structured response",
      `got ${r.status}`
    );
  }

  {
    const r = await POST("/v1/xrpl/trustline/check", { address: "rFakeAddress999" });
    assert(
      r.status === 200 || r.status === 404 || r.status === 400,
      "POST /v1/xrpl/trustline/check → structured response",
      `got ${r.status}`
    );
  }

  {
    // signing is disabled — should return a structured error, not a 500
    const r = await POST("/v1/xrpl/payment", {
      destination: "rFakeDest000",
      amount: "10",
      memo_bundle_hash: null,
    });
    assert(
      r.status === 200 || r.status === 400 || r.status === 422 || r.status === 503,
      "POST /v1/xrpl/payment (signing disabled) → structured response",
      `got ${r.status}`
    );
  }

  // ── 9. Validation / bad request shapes ────────────────────────────────────
  section("9 · Input validation");

  {
    const r = await POST("/v1/permit", {});
    assert(r.status === 422, "POST /v1/permit (missing subject) → 422", `got ${r.status}`);
  }

  {
    const r = await POST("/v1/verify", { bundle: "not-an-object" });
    assert(r.status === 422, "POST /v1/verify (bad shape) → 422", `got ${r.status}`);
  }

  {
    const r = await POST("/v1/settlement/verify", { bundle_hash: "x" });
    assert(r.status === 422, "POST /v1/settlement/verify (missing tx_hash) → 422", `got ${r.status}`);
  }

  // ── 10. Demo mode — keyword triggers ─────────────────────────────────────
  section("10 · Demo mode — keyword triggers");

  // Each address is exactly 25 chars and embeds the trigger keyword.
  const DEMO_PASS      = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"; // normal → all pass
  const DEMO_KYC_DENY  = "rKYC_DENYxd82kLm9Pq7Zr45w";
  const DEMO_SANCTION  = "rSANCTIONEDxkd82Lm9P7Zr4w";
  const DEMO_RESERVE   = "rRESERVE_FAILxk82Lm9P7Zr4";
  const DEMO_LIQUIDITY = "rLIQUIDITY_FAILxd82Lm9P7Z";
  const DEMO_UNAVAIL   = "rUNAVAILABLExkd82Lm9P7Zr4";

  // PASS — normal address, no keywords → all three providers approve
  {
    const r = await POST("/v1/permit", { subject: DEMO_PASS, action: "transfer", amount: 100 });
    const ok = assert(r.status === 200, "DEMO PASS → 200", `got ${r.status} — ${JSON.stringify(r.json)}`);
    if (ok) {
      const codes = r.json?.reason_codes ?? [];
      assert(codes.includes("KYC_VERIFIED"),     "DEMO PASS → KYC_VERIFIED",     JSON.stringify(codes));
      assert(codes.includes("SANCTIONS_PASSED"), "DEMO PASS → SANCTIONS_PASSED", JSON.stringify(codes));
      assert(codes.includes("RESERVE_BACKED"),   "DEMO PASS → RESERVE_BACKED",   JSON.stringify(codes));
    }
  }

  // KYC_DENY — KYC provider returns denied
  {
    const r = await POST("/v1/permit", { subject: DEMO_KYC_DENY, action: "transfer", amount: 100 });
    const ok = assert(r.status === 200, "DEMO KYC_DENY → 200", `got ${r.status}`);
    if (ok) {
      const codes = r.json?.reason_codes ?? [];
      assert(codes.includes("KYC_DENIED"), "DEMO KYC_DENY → KYC_DENIED in reason_codes", JSON.stringify(codes));
    }
  }

  // SANCTIONED — sanctions provider returns denied
  {
    const r = await POST("/v1/permit", { subject: DEMO_SANCTION, action: "transfer", amount: 100 });
    const ok = assert(r.status === 200, "DEMO SANCTIONED → 200", `got ${r.status}`);
    if (ok) {
      const codes = r.json?.reason_codes ?? [];
      assert(codes.includes("SANCTIONS_HIT"), "DEMO SANCTIONED → SANCTIONS_HIT in reason_codes", JSON.stringify(codes));
    }
  }

  // RESERVE_FAIL — reserve not_verified, liquidity still verified
  {
    const r = await POST("/v1/permit", { subject: DEMO_RESERVE, action: "transfer", amount: 100 });
    const ok = assert(r.status === 200, "DEMO RESERVE_FAIL → 200", `got ${r.status}`);
    if (ok) {
      const codes = r.json?.reason_codes ?? [];
      assert(codes.includes("RESERVE_STATUS_NOT_VERIFIED"), "DEMO RESERVE_FAIL → RESERVE_STATUS_NOT_VERIFIED", JSON.stringify(codes));
      assert(codes.includes("LIQUIDITY_STATUS_VERIFIED"),   "DEMO RESERVE_FAIL → LIQUIDITY_STATUS_VERIFIED",   JSON.stringify(codes));
    }
  }

  // LIQUIDITY_FAIL — liquidity not_verified, reserve still verified
  {
    const r = await POST("/v1/permit", { subject: DEMO_LIQUIDITY, action: "transfer", amount: 100 });
    const ok = assert(r.status === 200, "DEMO LIQUIDITY_FAIL → 200", `got ${r.status}`);
    if (ok) {
      const codes = r.json?.reason_codes ?? [];
      assert(codes.includes("RESERVE_STATUS_VERIFIED"),       "DEMO LIQUIDITY_FAIL → RESERVE_STATUS_VERIFIED",       JSON.stringify(codes));
      assert(codes.includes("LIQUIDITY_STATUS_NOT_VERIFIED"), "DEMO LIQUIDITY_FAIL → LIQUIDITY_STATUS_NOT_VERIFIED", JSON.stringify(codes));
    }
  }

  // UNAVAILABLE — all providers return unavailable, fail-closed → deny
  {
    const r = await POST("/v1/permit", { subject: DEMO_UNAVAIL, action: "transfer", amount: 100 });
    const ok = assert(r.status === 200, "DEMO UNAVAILABLE → 200", `got ${r.status}`);
    if (ok) {
      const codes = r.json?.reason_codes ?? [];
      const hasUnavailable = codes.some(c => c.includes("UNAVAILABLE") || c.includes("unavailable"));
      assert(hasUnavailable, "DEMO UNAVAILABLE → unavailable reason_code present", JSON.stringify(codes));
    }
  }

  // ── 11. Real XRPL testnet roundtrip ──────────────────────────────────────
  section("11 · Real XRPL testnet roundtrip");

  console.log(`  ${c.grey}destination=${ROUNDTRIP_DESTINATION} (override via ROUNDTRIP_DESTINATION env var)${c.reset}`);
  console.log(`  ${c.grey}waiting up to 60 s for submit_and_wait …${c.reset}`);

  const rt = await postWithTimeout(
    "/v1/demo/roundtrip",
    { destination: ROUNDTRIP_DESTINATION, amount_xrp: 0.001 },
    ROUNDTRIP_TIMEOUT_MS,
  );

  if (rt.timedOut) {
    fail("ROUNDTRIP → response within 60 s", "request timed out after 60 s");
  } else {
    const rtOk = assert(rt.status === 200, "ROUNDTRIP → 200", `got ${rt.status} — ${JSON.stringify(rt.json)}`);
    if (rtOk) {
      const j = rt.json;

      // permit
      assert(typeof j?.permit?.bundle_hash === "string" && j.permit.bundle_hash.length > 0,
        "ROUNDTRIP → permit.bundle_hash present", JSON.stringify(j?.permit));
      assert(j?.permit?.decision_result != null,
        "ROUNDTRIP → permit.decision_result present", JSON.stringify(j?.permit));

      // xrpl_tx
      const txHash = j?.xrpl_tx?.tx_hash ?? "";
      assert(/^[A-F0-9]{64}$/i.test(txHash),
        "ROUNDTRIP → xrpl_tx.tx_hash is 64-char hex", `got "${txHash}"`);
      assert(j?.xrpl_tx?.validated === true,
        "ROUNDTRIP → xrpl_tx.validated=true", `got ${j?.xrpl_tx?.validated}`);
      assert(j?.xrpl_tx?.ledger_index != null,
        "ROUNDTRIP → xrpl_tx.ledger_index present", `got ${j?.xrpl_tx?.ledger_index}`);
      assert(j?.xrpl_tx?.engine_result === "tesSUCCESS",
        "ROUNDTRIP → engine_result=tesSUCCESS", `got "${j?.xrpl_tx?.engine_result}"`);

      // memo verification
      assert(j?.memo_verification?.match === true,
        "ROUNDTRIP → memo matches bundle_hash", JSON.stringify(j?.memo_verification));
      assert(j?.memo_verification?.decoded_memo === j?.permit?.bundle_hash,
        "ROUNDTRIP → decoded_memo === bundle_hash", JSON.stringify(j?.memo_verification));

      // settlement
      assert(j?.settlement?.decision === "SETTLED_COMPLIANT",
        "ROUNDTRIP → settlement.decision=SETTLED_COMPLIANT", `got "${j?.settlement?.decision}"`);
      const sCodes = j?.settlement?.reason_codes ?? [];
      assert(sCodes.includes("BUNDLE_HASH_MEMO_MATCHED"),
        "ROUNDTRIP → BUNDLE_HASH_MEMO_MATCHED in settlement.reason_codes", JSON.stringify(sCodes));
      assert(sCodes.includes("XRPL_TX_VALIDATED"),
        "ROUNDTRIP → XRPL_TX_VALIDATED in settlement.reason_codes", JSON.stringify(sCodes));

      // proof artifact
      assert(j?.settlement?.proof_artifact?.bundle_hash != null,
        "ROUNDTRIP → proof_artifact.bundle_hash present", JSON.stringify(j?.settlement?.proof_artifact));

      if (rtOk) {
        console.log(`  ${c.cyan}  tx_hash     : ${txHash}${c.reset}`);
        console.log(`  ${c.cyan}  ledger_index: ${j?.xrpl_tx?.ledger_index}${c.reset}`);
        console.log(`  ${c.cyan}  bundle_hash : ${j?.permit?.bundle_hash}${c.reset}`);
        console.log(`  ${c.cyan}  memo_match  : ${j?.memo_verification?.match}${c.reset}`);
        console.log(`  ${c.cyan}  decision    : ${j?.settlement?.decision}${c.reset}`);
      }
    }
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  const total = passed + failed + skipped;
  console.log(`\n${c.bold}Results${c.reset}`);
  console.log(`  ${c.green}${passed} passed${c.reset}  ${c.red}${failed} failed${c.reset}  ${c.yellow}${skipped} skipped${c.reset}  ${c.grey}(${total} total)${c.reset}`);

  if (failures.length > 0) {
    console.log(`\n${c.bold}${c.red}Failures:${c.reset}`);
    for (const f of failures) {
      console.log(`  ${c.red}✗${c.reset} ${f.name}`);
      console.log(`    ${c.grey}${f.reason}${c.reset}`);
    }
  }

  console.log();
  process.exit(failed > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error(`\n${c.red}Fatal error: ${err.message}${c.reset}`);
  console.error(err);
  process.exit(1);
});
