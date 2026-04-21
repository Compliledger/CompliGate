import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Shared copy-to-clipboard helper used across panels.
 *
 * Tracks which value was most recently copied via a string `key`, so a single
 * hook instance can drive multiple copy buttons (e.g. bundle_hash, signature,
 * tx_hash, proof artifact JSON) and render a temporary "Copied" confirmation
 * next to the right button.
 *
 * The confirmation auto-clears after `resetMs` (default 2000ms). If the
 * Clipboard API is unavailable or rejects (e.g. insecure context, denied
 * permission), the call fails silently and `copied` is not updated.
 */
export function useCopyToClipboard(resetMs: number = 2000) {
  const [copied, setCopied] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  const copy = useCallback(
    async (text: string, key: string) => {
      try {
        if (typeof navigator === "undefined" || !navigator.clipboard) {
          return;
        }
        await navigator.clipboard.writeText(text);
        setCopied(key);
        if (timerRef.current) clearTimeout(timerRef.current);
        timerRef.current = setTimeout(
          () => setCopied((prev) => (prev === key ? null : prev)),
          resetMs,
        );
      } catch {
        // silent fail — clipboard API unavailable or denied
      }
    },
    [resetMs],
  );

  return { copied, copy };
}

export default useCopyToClipboard;
