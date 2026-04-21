/**
 * Centralized API client for the CompliGate frontend.
 *
 * Responsibilities:
 *  - Resolve the backend base URL from the shared config module
 *    (which in turn reads VITE_API_BASE).
 *  - Inject the API key (X-API-Key header) on every request, sourced from
 *    localStorage with a fallback to the build-time VITE_API_KEY value
 *    (also exposed via the shared config module).
 *  - Provide consistent timeout, JSON parsing and structured error handling
 *    so feature components do not duplicate fetch boilerplate.
 */

import { API_BASE, API_KEY, DEFAULT_TIMEOUT_MS } from "./config";

export { API_BASE, DEFAULT_TIMEOUT_MS };

const API_KEY_STORAGE_KEY = "compligate.apiKey";
const API_KEY_EVENT = "compligate:api-key-changed";

function envApiKey(): string {
  return API_KEY;
}

function safeStorage(): Storage | null {
  try {
    return typeof window !== "undefined" ? window.localStorage : null;
  } catch {
    return null;
  }
}

export function getApiKey(): string {
  const storage = safeStorage();
  if (storage) {
    const stored = storage.getItem(API_KEY_STORAGE_KEY);
    if (stored && stored.trim()) return stored.trim();
  }
  return envApiKey();
}

/** True when an API key was supplied via env (i.e. shipped with the build). */
export function hasEnvApiKey(): boolean {
  return envApiKey().length > 0;
}

/**
 * True when the active API key (the one `getApiKey()` would return) is the
 * build-time `VITE_API_KEY` value rather than a user-entered, browser-stored
 * key.
 */
export function isUsingEnvApiKey(): boolean {
  const env = envApiKey();
  if (!env) return false;
  const storage = safeStorage();
  const stored = storage?.getItem(API_KEY_STORAGE_KEY)?.trim();
  return !stored;
}

export function setApiKey(value: string): void {
  const storage = safeStorage();
  const trimmed = value.trim();
  if (!storage) return;
  if (trimmed) {
    storage.setItem(API_KEY_STORAGE_KEY, trimmed);
  } else {
    storage.removeItem(API_KEY_STORAGE_KEY);
  }
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent(API_KEY_EVENT));
  }
}

export function clearApiKey(): void {
  setApiKey("");
}

/**
 * Subscribe to API key changes (including changes from other tabs).
 * Returns an unsubscribe function.
 */
export function subscribeToApiKey(listener: () => void): () => void {
  if (typeof window === "undefined") return () => {};
  const storageHandler = (e: StorageEvent) => {
    if (e.key === API_KEY_STORAGE_KEY) listener();
  };
  const customHandler = () => listener();
  window.addEventListener("storage", storageHandler);
  window.addEventListener(API_KEY_EVENT, customHandler);
  return () => {
    window.removeEventListener("storage", storageHandler);
    window.removeEventListener(API_KEY_EVENT, customHandler);
  };
}

export class ApiError extends Error {
  readonly status: number;
  readonly data: unknown;

  constructor(message: string, status: number, data: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data = data;
  }
}

export class ApiTimeoutError extends ApiError {
  constructor() {
    super("Request timed out. Please try again.", 0, null);
    this.name = "ApiTimeoutError";
  }
}

export class ApiNetworkError extends ApiError {
  constructor(message: string) {
    super(message, 0, null);
    this.name = "ApiNetworkError";
  }
}

function extractErrorMessage(data: unknown, fallback: string): string {
  if (!data) return fallback;
  if (typeof data === "string") return data;
  const d = data as Record<string, unknown>;
  const detail = d.detail;
  if (typeof detail === "string") return detail;
  if (typeof detail === "object" && detail !== null) {
    const obj = detail as Record<string, unknown>;
    const reason = obj.reason;
    const error = obj.error;
    if (typeof reason === "string") return reason;
    if (typeof error === "string") return error;
    try {
      return JSON.stringify(detail);
    } catch {
      return fallback;
    }
  }
  if (typeof d.message === "string") return d.message;
  return fallback;
}

export type ApiFetchOptions = Omit<RequestInit, "body" | "signal"> & {
  /** JSON-serialisable body. Sets Content-Type automatically. */
  json?: unknown;
  /** Raw body (takes precedence over json). */
  body?: BodyInit | null;
  /** Override the default request timeout. */
  timeoutMs?: number;
  /** External AbortSignal that can also cancel the request. */
  signal?: AbortSignal;
};

/**
 * Issue an authenticated request to the CompliGate backend.
 *
 * Always:
 *   - prefixes the path with API_BASE (path may be absolute or start with "/")
 *   - applies a request timeout (defaults to DEFAULT_TIMEOUT_MS)
 *   - attaches `X-API-Key` when an API key is configured
 *   - parses a JSON body when present
 *   - throws ApiError / ApiTimeoutError / ApiNetworkError on failure
 */
export async function apiFetch<T = unknown>(
  path: string,
  options: ApiFetchOptions = {},
): Promise<T> {
  const { json, timeoutMs, signal, headers, ...rest } = options;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const onExternalAbort = () => controller.abort();
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener("abort", onExternalAbort, { once: true });
  }

  const finalHeaders = new Headers(headers ?? {});
  if (json !== undefined && !finalHeaders.has("Content-Type")) {
    finalHeaders.set("Content-Type", "application/json");
  }
  if (!finalHeaders.has("Accept")) {
    finalHeaders.set("Accept", "application/json");
  }
  const apiKey = getApiKey();
  if (apiKey && !finalHeaders.has("X-API-Key")) {
    finalHeaders.set("X-API-Key", apiKey);
  }

  const url = path.startsWith("http") ? path : `${API_BASE}${path.startsWith("/") ? path : `/${path}`}`;

  let response: Response;
  try {
    response = await fetch(url, {
      ...rest,
      headers: finalHeaders,
      body: json !== undefined ? JSON.stringify(json) : (rest as RequestInit).body ?? null,
      signal: controller.signal,
    });
  } catch (e: unknown) {
    if (e instanceof Error && e.name === "AbortError") {
      throw new ApiTimeoutError();
    }
    throw new ApiNetworkError(e instanceof Error ? e.message : "Network error.");
  } finally {
    clearTimeout(timeout);
    if (signal) signal.removeEventListener("abort", onExternalAbort);
  }

  // Try to parse JSON; tolerate empty/non-JSON responses.
  const text = await response.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  if (!response.ok) {
    let fallback = `Request failed with status ${response.status}`;
    if (response.status === 401) {
      fallback = "Unauthorized — check that your API key is set and valid.";
    } else if (response.status === 403) {
      fallback = "Forbidden — this API key is not allowed to perform this action.";
    }
    throw new ApiError(extractErrorMessage(data, fallback), response.status, data);
  }

  return data as T;
}

/** Convenience: errors -> human-readable strings, including network/timeout. */
export function describeError(err: unknown, fallback = "Request failed."): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return fallback;
}
