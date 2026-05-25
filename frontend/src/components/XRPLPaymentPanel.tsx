import { useEffect, useState, type KeyboardEvent } from "react";

import { apiPost, describeError } from "../lib/api";
import { useCopyToClipboard } from "../lib/useCopyToClipboard";
import { getXrplExplorerUrl } from "../lib/xrplExplorer";
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
  /**
   * XRPL payment result, owned by the parent so other panels and the
   * top-level UI can react to it. The panel keeps the destination/amount
   * inputs, loading, and error state local because they are only meaningful
   * inside this panel.
   */
  result: XRPLPaymentResponse | null;
  /** Setter for the shared XRPL payment result. */
  onResult: (result: XRPLPaymentResponse | null) => void;
};

export default function XRPLPaymentPanel({ permit, panelNumber, order, result, onResult }: Props) {
  const [destination, setDestination] = useState("");
  const [amount, setAmount] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { copied, copy: copyToClipboard } = useCopyToClipboard();

  const memoBundleHash = permit?.bundle_hash ?? null;

  useEffect(() => {
    if (permit) {
      const counterparty = permit.bundle?.constraints?.allowed_counterparty;
      if (counterparty && !destination) setDestination(counterparty);
      if (!amount) setAmount("1");
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [permit?.bundle_hash]);

  async function submitPayment() {
    setError(null);
    onResult(null);

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
      onResult(data);
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
    onResult(null);
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

      <label className="label">Amount (XRP)</label>
      <input
        className="input"
        type="text"
        inputMode="decimal"
        value={amount}
        onChange={(e) => setAmount(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="e.g. 1"
      />
      <p className="muted" style={{ fontSize: "0.78rem", marginTop: "-0.25rem" }}>
        Testnet payments are in XRP (max 1 XRP auto-applied). The permit compliance check is in RLUSD.
      </p>

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

      {result?.testnet_amount_capped && (
        <StatusMessage variant="empty" title="Amount adjusted for testnet">
          Requested amount exceeded the testnet wallet balance — capped to 1 XRP. Compliance authorization remains unchanged.
        </StatusMessage>
      )}

      {result?.demo_settlement_note && (
        <StatusMessage variant="empty" title="Demo settlement path">
          {result.demo_settlement_note}
        </StatusMessage>
      )}

      {result && (() => {
        const ok = result.submitted;
        const checkCls = ok ? "check" : "check checkFail";
        const checkSym = ok ? "✔" : "✘";
        const explorerUrl = getXrplExplorerUrl(result.tx_hash, result.network);
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
              {explorerUrl && (
                <a
                  className="copyBtn"
                  href={explorerUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  title={`View tx_hash on explorer (${result.network})`}
                >
                  View on Explorer ↗
                </a>
              )}
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
              <span className="summaryLabel">Settlement Asset</span>
              <span className="summaryValue">{result.currency}</span>
            </div>

            {result.permit_asset && result.permit_asset !== result.currency && (
              <div className="verifyRow">
                <span className="check">—</span>
                <span className="summaryLabel">Permit Asset (compliance)</span>
                <span className="summaryValue" style={{ color: "var(--text-warn, #b08d57)" }}>
                  {result.permit_asset}
                </span>
              </div>
            )}

            {result.settlement_path && (
              <div className="verifyRow">
                <span className={checkCls}>{checkSym}</span>
                <span className="summaryLabel">Settlement Path</span>
                <span className="summaryValue">{result.settlement_path}</span>
              </div>
            )}

            {result.trustline_mode && (
              <div className="verifyRow">
                <span className="check">—</span>
                <span className="summaryLabel">Trustline Check</span>
                <span className="summaryValue" style={{ color: result.trustline_mode === "advisory" ? "var(--text-warn, #b08d57)" : undefined }}>
                  {result.trustline_mode === "advisory" ? "Advisory (not enforced on XRP path)" : result.trustline_mode}
                </span>
              </div>
            )}

            <div className="verifyRow">
              <span className={checkCls}>{checkSym}</span>
              <span className="summaryLabel">Issuer</span>
              <span className="summaryValue commitValueMono breakAll">
                {result.issuer || "—"}
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
