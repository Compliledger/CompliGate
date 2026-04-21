import { useState, type KeyboardEvent } from "react";

import { apiPost, describeError } from "../lib/api";
import { useCopyToClipboard } from "../lib/useCopyToClipboard";
import PanelNumber from "./PanelNumber";
import StatusMessage from "./StatusMessage";
import type { PermitResponse, XRPLPaymentResponse } from "../types/api";

type XRPLPaymentRequestBody = {
  destination: string;
  amount: string;
  memo_bundle_hash?: string;
};

type Props = {
  /**
   * Active permit, when one has been issued. When present, its
   * `bundle_hash` is automatically attached to the payment request as
   * `memo_bundle_hash` so the resulting XRPL transaction is bound to the
   * compliance proof bundle.
   */
  permit: PermitResponse | null;
  /** Optional panel number for visual ordering alongside other cards. */
  panelNumber?: number;
  /** Optional CSS flex order, used to position among sibling panels. */
  order?: number;
};

export default function XRPLPaymentPanel({ permit, panelNumber, order }: Props) {
  const [destination, setDestination] = useState("");
  const [amount, setAmount] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<XRPLPaymentResponse | null>(null);
  const { copied, copy: copyToClipboard } = useCopyToClipboard();

  const memoBundleHash = permit?.bundle_hash ?? null;

  async function submitPayment() {
    setError(null);
    setResult(null);

    const trimmedDestination = destination.trim();
    const trimmedAmount = amount.trim();

    if (!trimmedDestination) {
      setError("Enter a destination XRPL address.");
      return;
    }
    if (!trimmedAmount) {
      setError("Enter an amount to send.");
      return;
    }
    const parsedAmount = Number(trimmedAmount);
    if (!isFinite(parsedAmount) || parsedAmount <= 0) {
      setError("Amount must be a positive number.");
      return;
    }

    const body: XRPLPaymentRequestBody = {
      destination: trimmedDestination,
      amount: trimmedAmount,
    };
    if (memoBundleHash) {
      body.memo_bundle_hash = memoBundleHash;
    }

    setLoading(true);
    try {
      const data = await apiPost<XRPLPaymentResponse>("/v1/xrpl/payment", body);
      setResult(data);
    } catch (e: unknown) {
      setError(describeError(e, "Failed to submit XRPL payment."));
    } finally {
      setLoading(false);
    }
  }

  function handleKeyDown(e: KeyboardEvent) {
    if (e.key === "Enter" && !loading && destination.trim() && amount.trim()) {
      submitPayment();
    }
  }

  function handleClear() {
    setDestination("");
    setAmount("");
    setError(null);
    setResult(null);
  }

  return (
    <section className="card" style={order !== undefined ? { order } : undefined}>
      <h2>
        {panelNumber !== undefined && <PanelNumber n={panelNumber} />}
        Submit XRPL Payment
      </h2>
      <p className="muted">
        Submit an XRPL payment via the CompliGate backend. When a permit is
        active its bundle hash is attached automatically as a memo, binding the
        on-ledger transaction to the compliance proof.
      </p>

      <label className="label">Destination Address</label>
      <input
        className="input"
        value={destination}
        onChange={(e) => setDestination(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="r..."
        spellCheck={false}
      />

      <label className="label">Amount</label>
      <input
        className="input"
        type="text"
        inputMode="decimal"
        value={amount}
        onChange={(e) => setAmount(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="e.g. 100"
      />

      {memoBundleHash ? (
        <div className="verifyRows">
          <div className="verifyRow">
            <span className="check">✔</span>
            <span className="summaryLabel">Memo Bundle Hash</span>
            <span className="summaryValue commitValueMono breakAll">
              {memoBundleHash}
            </span>
          </div>
        </div>
      ) : (
        <p className="muted">
          No active permit — payment will be submitted without a bundle-hash memo.
        </p>
      )}

      <div className="row">
        <button
          className="btn primary"
          onClick={submitPayment}
          disabled={!destination.trim() || !amount.trim() || loading}
        >
          {loading ? "Submitting…" : "Submit Payment"}
        </button>
        <button className="btn" onClick={handleClear} disabled={loading}>
          Clear
        </button>
      </div>

      {error && (
        <StatusMessage variant="error" title="Payment failed">
          {error}
        </StatusMessage>
      )}

      {!error && loading && (
        <StatusMessage variant="loading" title="Submitting payment…">
          Sending the transaction to the XRPL via the CompliGate backend.
        </StatusMessage>
      )}

      {!error && !loading && !result && (
        <StatusMessage variant="empty" title="No payment submitted yet">
          Fill in destination and amount, then submit to see the result here.
        </StatusMessage>
      )}

      {result && (() => {
        const ok = result.submitted;
        const checkCls = ok ? "check" : "check checkFail";
        const checkSym = ok ? "✔" : "✘";
        return (
        <div className="verifyResult">
          <div className={`verifyHeader ${ok ? "good" : "bad"}`}>
            <span className={`verifyIcon ${ok ? "good" : "bad"}`}>
              {checkSym}
            </span>
            {ok ? "Submitted" : "Not Submitted"} — {result.engine_result}
          </div>

          <div className="verifyRows">
            <div className="verifyRow">
              <span className={checkCls}>{checkSym}</span>
              <span className="summaryLabel">Submitted</span>
              <span className="summaryValue">{ok ? "Yes" : "No"}</span>
            </div>

            <div className="verifyRow">
              <span className={checkCls}>{checkSym}</span>
              <span className="summaryLabel">TX Hash</span>
              <span className="summaryValue commitValueMono breakAll">
                {result.tx_hash}
              </span>
              <button
                className="copyBtn"
                onClick={() => copyToClipboard(result.tx_hash, "pay_tx_hash")}
                title="Copy tx_hash"
              >
                {copied === "pay_tx_hash" ? "✔ Copied" : "Copy"}
              </button>
            </div>

            <div className="verifyRow">
              <span
                className={
                  result.engine_result === "tesSUCCESS"
                    ? "check"
                    : "check checkFail"
                }
              >
                {result.engine_result === "tesSUCCESS" ? "✔" : "✘"}
              </span>
              <span className="summaryLabel">Engine Result</span>
              <span className="summaryValue">{result.engine_result}</span>
            </div>

            <div className="verifyRow">
              <span className={checkCls}>{checkSym}</span>
              <span className="summaryLabel">Currency</span>
              <span className="summaryValue">{result.currency}</span>
            </div>

            <div className="verifyRow">
              <span className={checkCls}>{checkSym}</span>
              <span className="summaryLabel">Issuer</span>
              <span className="summaryValue commitValueMono breakAll">
                {result.issuer}
              </span>
            </div>

            <div className="verifyRow">
              <span className={checkCls}>{checkSym}</span>
              <span className="summaryLabel">Amount</span>
              <span className="summaryValue">{result.amount}</span>
            </div>

            <div className="verifyRow">
              <span className={checkCls}>{checkSym}</span>
              <span className="summaryLabel">Destination</span>
              <span className="summaryValue commitValueMono breakAll">
                {result.destination}
              </span>
            </div>

            {result.proof_link && (
              <>
                <div className="verifyRow">
                  <span className={checkCls}>{checkSym}</span>
                  <span className="summaryLabel">Proof Link · Bundle Hash</span>
                  <span className="summaryValue commitValueMono breakAll">
                    {result.proof_link.bundle_hash}
                  </span>
                  <button
                    className="copyBtn"
                    onClick={() =>
                      copyToClipboard(
                        result.proof_link!.bundle_hash,
                        "pay_proof_bundle_hash",
                      )
                    }
                    title="Copy bundle_hash"
                  >
                    {copied === "pay_proof_bundle_hash" ? "✔ Copied" : "Copy"}
                  </button>
                </div>
                <div className="verifyRow">
                  <span className={checkCls}>{checkSym}</span>
                  <span className="summaryLabel">Proof Link · TX Hash</span>
                  <span className="summaryValue commitValueMono breakAll">
                    {result.proof_link.tx_hash}
                  </span>
                  <button
                    className="copyBtn"
                    onClick={() =>
                      copyToClipboard(
                        result.proof_link!.tx_hash,
                        "pay_proof_tx_hash",
                      )
                    }
                    title="Copy tx_hash"
                  >
                    {copied === "pay_proof_tx_hash" ? "✔ Copied" : "Copy"}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
        );
      })()}
    </section>
  );
}
