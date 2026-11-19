import { QueryClient, QueryObserver } from "@tanstack/react-query";
import { describe, expect, it, vi } from "vitest";

import {
  MAX_429_RETRIES,
  queryClient,
  retryAfterMs,
  retryDelay,
  shouldRetry,
} from "./queryClient";

function httpError(
  status: number,
  headers: Record<string, string> = {},
): Error {
  return Object.assign(new Error(`Request failed with status code ${status}`), {
    status,
    response: { status, headers },
  });
}

describe("query retry (#2944)", () => {
  it("retries a 429 up to the cap", () => {
    const err = httpError(429);
    for (let n = 0; n < MAX_429_RETRIES; n++)
      expect(shouldRetry(n, err)).toBe(true);
    expect(shouldRetry(MAX_429_RETRIES, err)).toBe(false);
  });

  it.each([400, 401, 403, 404, 409, 422])("never retries a %i", (status) => {
    expect(shouldRetry(0, httpError(status))).toBe(false);
  });

  it("keeps two retries for a 5xx or a network error", () => {
    expect(shouldRetry(0, httpError(503))).toBe(true);
    expect(shouldRetry(1, httpError(503))).toBe(true);
    expect(shouldRetry(2, httpError(503))).toBe(false);
    expect(shouldRetry(1, new Error("Network Error"))).toBe(true);
  });

  it("waits what Retry-After says, capped", () => {
    expect(retryDelay(0, httpError(429, { "retry-after": "2" }))).toBe(2000);
    expect(retryDelay(0, httpError(429, { "retry-after": "3600" }))).toBe(
      30_000,
    );
    const now = Date.parse("2026-10-28T12:00:00Z");
    expect(
      retryAfterMs(
        httpError(429, { "retry-after": "Wed, 28 Oct 2026 12:00:04 GMT" }),
        now,
      ),
    ).toBe(4000);
  });

  it("backs off briefly without Retry-After", () => {
    const err = httpError(429);
    expect([0, 1, 2].map((n) => retryDelay(n, err))).toEqual([500, 1000, 2000]);
    expect(
      retryAfterMs(httpError(429, { "retry-after": "soon" })),
    ).toBeUndefined();
  });

  it("is what the shared client uses", () => {
    const opts = queryClient.getDefaultOptions().queries;
    expect(opts?.retry).toBe(shouldRetry);
    expect(opts?.retryDelay).toBe(retryDelay);
  });

  it("a query that met a 429 fills in on the retry, not the next refetch", async () => {
    vi.useFakeTimers();
    try {
      const client = new QueryClient({
        defaultOptions: { queries: { retry: shouldRetry, retryDelay } },
      });
      const fn = vi
        .fn()
        .mockRejectedValueOnce(httpError(429))
        .mockResolvedValueOnce({ status: "ok" });
      const observer = new QueryObserver(client, {
        queryKey: ["platform-health"],
        queryFn: fn,
      });
      const unsubscribe = observer.subscribe(() => undefined);
      await vi.advanceTimersByTimeAsync(600);
      expect(fn).toHaveBeenCalledTimes(2);
      expect(observer.getCurrentResult().data).toEqual({ status: "ok" });
      unsubscribe();
      client.clear();
    } finally {
      vi.useRealTimers();
    }
  });

  it("a 404 is not retried", async () => {
    vi.useFakeTimers();
    try {
      const client = new QueryClient({
        defaultOptions: { queries: { retry: shouldRetry, retryDelay } },
      });
      const fn = vi.fn().mockRejectedValue(httpError(404));
      const observer = new QueryObserver(client, {
        queryKey: ["x"],
        queryFn: fn,
      });
      const unsubscribe = observer.subscribe(() => undefined);
      await vi.advanceTimersByTimeAsync(5000);
      expect(fn).toHaveBeenCalledTimes(1);
      expect(observer.getCurrentResult().status).toBe("error");
      unsubscribe();
      client.clear();
    } finally {
      vi.useRealTimers();
    }
  });
});
