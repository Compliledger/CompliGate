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
    }
  }

  return (
    <section className="card" style={{ order: 8 }}>
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
        </button>
        <button
          className="btn"
          onClick={() => {
            setTxLookupHash("");
            setTxLookupResult(null);
            setTxLookupError(null);
          }}
        >
          Clear
        </button>
        {txLookupResult?.tx_hash && onUseHash && (
          <button
            className="btn"
            onClick={() => onUseHash(txLookupResult.tx_hash)}
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
          </div>

          <div className="verifyRows">
            <div className="verifyRow">
              <span className="check">✔</span>
              <span className="summaryLabel">TX Hash</span>
              <span className="summaryValue commitValueMono breakAll">{txLookupResult.tx_hash}</span>
              <button
                className="copyBtn"
                onClick={() => copyToClipboard(txLookupResult.tx_hash, "txlookup_hash")}
                title="Copy TX hash"
              >
                {copied === "txlookup_hash" ? "✔ Copied" : "Copy"}
              </button>
            </div>
            <div className="verifyRow">
              <span className="check">✔</span>
              <span className="summaryLabel">Type</span>
              <span className="summaryValue">{txLookupResult.transaction_type}</span>
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
              </div>
            )}
            <div className="verifyRow">
              <span className="check">✔</span>
              <span className="summaryLabel">Currency</span>
              <span className="summaryValue">{txLookupResult.amount.currency}</span>
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
              </div>
            )}
            <div className="verifyRow">
              <span className="check">✔</span>
              <span className="summaryLabel">Network</span>
              <span className="summaryValue">{txLookupResult.network}</span>
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
        <StatusMessage variant="loading" title="Looking up transaction…">
          Querying the XRPL for the transaction details.
        </StatusMessage>
      )}
      {!txLookupError && !txLookupLoading && !txLookupResult && (
        <StatusMessage variant="empty" title="No transaction looked up yet">
          Enter an XRPL transaction hash above to inspect its details.
        </StatusMessage>
      )}
    </section>
  );
}
