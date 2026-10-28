import { QueryClient } from "@tanstack/react-query";

// #2944 — a 429 is the one 4xx worth retrying: it says "not now", not "never".
// The frontend nginx rate limits /health and /metrics per client, so a query
// that met a spent allowance would otherwise stay empty until its next
// refetch.
export const MAX_429_RETRIES = 3;
const MAX_RETRY_AFTER_MS = 30_000;

function statusOf(error: unknown): number | undefined {
  if (error instanceof Error && "status" in error) {
    const status = (error as { status: unknown }).status;
    if (typeof status === "number") return status;
  }
  return undefined;
}

/** ``Retry-After`` as milliseconds, from delta-seconds or an HTTP date. */
export function retryAfterMs(
  error: unknown,
  now: number = Date.now(),
): number | undefined {
  const headers = (
    error as { response?: { headers?: Record<string, unknown> } } | null
  )?.response?.headers;
  const raw = headers?.["retry-after"];
  if (typeof raw !== "string" || raw.trim() === "") return undefined;
  const value = raw.trim();
  if (/^\d+$/.test(value)) return Number(value) * 1000;
  const date = Date.parse(value);
  if (Number.isNaN(date)) return undefined;
  return Math.max(0, date - now);
}

export function shouldRetry(failureCount: number, error: unknown): boolean {
  const status = statusOf(error);
  if (status === 429) return failureCount < MAX_429_RETRIES;
  // Any other 4xx is the request's fault: retrying cannot change the answer.
  if (status !== undefined && status >= 400 && status < 500) return false;
  return failureCount < 2;
}

export function retryDelay(failureCount: number, error: unknown): number {
  if (statusOf(error) === 429) {
    const after = retryAfterMs(error);
    if (after !== undefined) return Math.min(after, MAX_RETRY_AFTER_MS);
    // Short backoff: the limit refills at 5 requests a second.
    return 500 * 2 ** failureCount;
  }
  // React Query's own default.
  return Math.min(1000 * 2 ** failureCount, 30_000);
}

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: shouldRetry,
      retryDelay,
    },
  },
});
