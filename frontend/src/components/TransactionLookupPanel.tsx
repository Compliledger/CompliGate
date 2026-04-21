import { useState } from "react";

import { apiGet, describeError } from "../lib/api";
import { useCopyToClipboard } from "../lib/useCopyToClipboard";
import StatusMessage from "./StatusMessage";

/**
 * TransactionLookupPanel
 *
 * Self-contained supplemental panel that looks up a real XRPL transaction by
 * hash and renders its details. All form state (input hash, loading, error,
 * and result) is local to this panel because it is not consumed by any other
 * panel. The optional `onUseHash` callback lets the parent forward the
 * looked-up hash into the shared "settled transaction" state used by the
 * settlement verification flow.
 */
import StatusMessage from "./StatusMessage";
import { useCopyToClipboard } from "../lib/useCopyToClipboard";
import { checkClass, checkSymbol } from "../lib/format";

type TxLookupAmount = {
  currency: string;
  value: string;
  issuer: string;
};

type TxLookupResponse = {
  tx_hash: string;
  validated: boolean;
  transaction_type: string;
  account: string;
  destination: string;
  amount: TxLookupAmount;
  engine_result: string;
  network: string;
};

function checkClass(valid: boolean) {
  return valid ? "check" : "check checkFail";
}

function checkSymbol(valid: boolean) {
  return valid ? "✔" : "✘";
}

type Props = {
  /**
   * Optional handler invoked when the user clicks "Use Hash for Verification".
   * The looked-up transaction hash is forwarded so the parent can push it into
   * the shared settled-transaction-hash state.
   */
  onUseHash?: (txHash: string) => void;
};

export default function TransactionLookupPanel({ onUseHash }: Props) {
  const [txLookupHash, setTxLookupHash] = useState("");
  const [txLookupResult, setTxLookupResult] = useState<TxLookupResponse | null>(null);
  const [txLookupError, setTxLookupError] = useState<string | null>(null);
  const [txLookupLoading, setTxLookupLoading] = useState(false);
  const { copied, copy: copyToClipboard } = useCopyToClipboard();

  async function lookupTransaction() {
    if (!txLookupHash.trim()) return;
    setTxLookupError(null);
    setTxLookupResult(null);
    setTxLookupLoading(true);

    try {
      const data = await apiGet<TxLookupResponse>(
        `/v1/xrpl/tx/${encodeURIComponent(txLookupHash.trim())}`,
      );
      setTxLookupResult(data);
    } catch (e: unknown) {
      setTxLookupError(describeError(e, "Failed to look up transaction."));
    } finally {
      setTxLookupLoading(false);
type Props = {
  /**
   * Optional callback invoked when the user clicks "Use Hash for
   * Verification". Allows the parent to forward the looked-up hash to
   * the settlement verification panel.
   */
  onUseHash?: (txHash: string) => void;
  /** Optional CSS flex order, used to position among sibling panels. */
  order?: number;
};

/**
 * TransactionLookupPanel
 *
 * Supplemental panel that looks up a real XRPL transaction by hash and
 * displays its key fields. When `onUseHash` is provided, exposes a
 * shortcut button that forwards the looked-up hash to the settlement
 * verification flow.
 */
export default function TransactionLookupPanel({ onUseHash, order }: Props) {
  const [hash, setHash] = useState("");
  const [result, setResult] = useState<TxLookupResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { copied, copy: copyToClipboard } = useCopyToClipboard();

  async function lookupTransaction() {
    const trimmed = hash.trim();
    if (!trimmed) return;
    setError(null);
    setResult(null);
    setLoading(true);

    try {
      const data = await apiGet<TxLookupResponse>(
        `/v1/xrpl/tx/${encodeURIComponent(trimmed)}`,
      );
      setResult(data);
    } catch (e: unknown) {
      setError(describeError(e, "Failed to look up transaction."));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="card" style={{ order: 8 }}>
    <section className="card" style={order !== undefined ? { order } : undefined}>
      <h2>Transaction Lookup</h2>
      <p className="muted">
        Look up a real XRPL transaction by hash to inspect its details.
      </p>

      <label className="label">Transaction Hash</label>
      <input
        className="input"
        value={txLookupHash}
        onChange={(e) => setTxLookupHash(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && txLookupHash.trim() && !txLookupLoading) lookupTransaction();
        value={hash}
        onChange={(e) => setHash(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && hash.trim() && !loading) lookupTransaction();
        }}
        placeholder="Enter XRPL transaction hash..."
        spellCheck={false}
      />

      <div className="row">
        <button
          className="btn primary"
          onClick={lookupTransaction}
          disabled={!txLookupHash.trim() || txLookupLoading}
        >
          {txLookupLoading ? "Looking up…" : "Look Up Transaction"}
          disabled={!hash.trim() || loading}
        >
          {loading ? "Looking up…" : "Look Up Transaction"}
        </button>
        <button
          className="btn"
          onClick={() => {
            setTxLookupHash("");
            setTxLookupResult(null);
            setTxLookupError(null);
            setHash("");
            setResult(null);
            setError(null);
          }}
        >
          Clear
        </button>
        {txLookupResult?.tx_hash && onUseHash && (
          <button
            className="btn"
            onClick={() => onUseHash(txLookupResult.tx_hash)}
        {result?.tx_hash && onUseHash && (
          <button
            className="btn"
            onClick={() => onUseHash(result.tx_hash)}
          >
            Use Hash for Verification
          </button>
        )}
      </div>

      {txLookupResult && (
        <div className="verifyResult">
          <div className={`verifyHeader ${txLookupResult.validated ? "good" : "bad"}`}>
            <span className={`verifyIcon ${txLookupResult.validated ? "good" : "bad"}`}>
              {txLookupResult.validated ? "✔" : "✘"}
            </span>
            {txLookupResult.validated ? "Validated" : "Not Validated"}
      {result && (
        <div className="verifyResult">
          <div className={`verifyHeader ${result.validated ? "good" : "bad"}`}>
            <span className={`verifyIcon ${result.validated ? "good" : "bad"}`}>
              {result.validated ? "✔" : "✘"}
            </span>
            {result.validated ? "Validated" : "Not Validated"}
          </div>

          <div className="verifyRows">
            <div className="verifyRow">
              <span className="check">✔</span>
              <span className="summaryLabel">TX Hash</span>
              <span className="summaryValue commitValueMono breakAll">{txLookupResult.tx_hash}</span>
              <button
                className="copyBtn"
                onClick={() => copyToClipboard(txLookupResult.tx_hash, "txlookup_hash")}
              <span className="summaryValue commitValueMono breakAll">{result.tx_hash}</span>
              <button
                className="copyBtn"
                onClick={() => copyToClipboard(result.tx_hash, "txlookup_hash")}
                title="Copy TX hash"
              >
                {copied === "txlookup_hash" ? "✔ Copied" : "Copy"}
              </button>
            </div>
            <div className="verifyRow">
              <span className="check">✔</span>
              <span className="summaryLabel">Type</span>
              <span className="summaryValue">{txLookupResult.transaction_type}</span>
              <span className="summaryValue">{result.transaction_type}</span>
            </div>
            <div className="verifyRow">
              <span className="check">✔</span>
              <span className="summaryLabel">Account</span>
              <span className="summaryValue commitValueMono breakAll">{txLookupResult.account}</span>
            </div>
            {txLookupResult.destination && (
              <div className="verifyRow">
                <span className="check">✔</span>
                <span className="summaryLabel">Destination</span>
                <span className="summaryValue commitValueMono breakAll">{txLookupResult.destination}</span>
              <span className="summaryValue commitValueMono breakAll">{result.account}</span>
            </div>
            {result.destination && (
              <div className="verifyRow">
                <span className="check">✔</span>
                <span className="summaryLabel">Destination</span>
                <span className="summaryValue commitValueMono breakAll">{result.destination}</span>
              </div>
            )}
            <div className="verifyRow">
              <span className="check">✔</span>
              <span className="summaryLabel">Currency</span>
              <span className="summaryValue">{txLookupResult.amount.currency}</span>
              <span className="summaryValue">{result.amount.currency}</span>
            </div>
            <div className="verifyRow">
              <span className="check">✔</span>
              <span className="summaryLabel">Amount</span>
              <span className="summaryValue">{txLookupResult.amount.value}</span>
            </div>
            {txLookupResult.amount.issuer && (
              <div className="verifyRow">
                <span className="check">✔</span>
                <span className="summaryLabel">Issuer</span>
                <span className="summaryValue commitValueMono breakAll">{txLookupResult.amount.issuer}</span>
              </div>
            )}
            {txLookupResult.engine_result && (
              <div className="verifyRow">
                <span className={checkClass(txLookupResult.engine_result === "tesSUCCESS")}>
                  {checkSymbol(txLookupResult.engine_result === "tesSUCCESS")}
                </span>
                <span className="summaryLabel">Engine Result</span>
                <span className="summaryValue">{txLookupResult.engine_result}</span>
              <span className="summaryValue">{result.amount.value}</span>
            </div>
            {result.amount.issuer && (
              <div className="verifyRow">
                <span className="check">✔</span>
                <span className="summaryLabel">Issuer</span>
                <span className="summaryValue commitValueMono breakAll">{result.amount.issuer}</span>
              </div>
            )}
            {result.engine_result && (
              <div className="verifyRow">
                <span className={checkClass(result.engine_result === "tesSUCCESS")}>
                  {checkSymbol(result.engine_result === "tesSUCCESS")}
                </span>
                <span className="summaryLabel">Engine Result</span>
                <span className="summaryValue">{result.engine_result}</span>
              </div>
            )}
            <div className="verifyRow">
              <span className="check">✔</span>
              <span className="summaryLabel">Network</span>
              <span className="summaryValue">{txLookupResult.network}</span>
              <span className="summaryValue">{result.network}</span>
            </div>
          </div>
        </div>
      )}

      {txLookupError && (
        <StatusMessage variant="error" title="Transaction lookup failed">
          {txLookupError}
        </StatusMessage>
      )}
      {!txLookupError && txLookupLoading && (
      {error && (
        <StatusMessage variant="error" title="Transaction lookup failed">
          {error}
        </StatusMessage>
      )}
      {!error && loading && (
        <StatusMessage variant="loading" title="Looking up transaction…">
          Querying the XRPL for the transaction details.
        </StatusMessage>
      )}
      {!txLookupError && !txLookupLoading && !txLookupResult && (
      {!error && !loading && !result && (
        <StatusMessage variant="empty" title="No transaction looked up yet">
          Enter an XRPL transaction hash above to inspect its details.
        </StatusMessage>
      )}
    </section>
  );
}
