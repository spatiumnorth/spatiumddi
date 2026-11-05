/**
 * @vitest-environment jsdom
 *
 * A failed metrics read says it failed; only a 403 reads as missing access (#3541).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const fail = vi.hoisted(() => ({ err: null as unknown }));
vi.mock("@/lib/api", async (orig) => {
  const mod = await orig<typeof import("@/lib/api")>();
  return {
    ...mod,
    metricsApi: {
      ...mod.metricsApi,
      dnsTimeseries: () => Promise.reject(fail.err),
      dhcpTimeseries: () => Promise.reject(fail.err),
    },
  };
});

import { DHCPTrafficCard, DNSQueryRateCard } from "./MetricsCharts";

afterEach(cleanup);

function renderCard(el: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={qc}>{el}</QueryClientProvider>);
}

describe("metrics card failure words", () => {
  it("a network error is a fetch error, not a role problem", async () => {
    fail.err = new Error("Network Error");
    renderCard(<DHCPTrafficCard />);
    expect(await screen.findByText(/couldn't be loaded/)).toBeTruthy();
    expect(screen.queryByText(/Your role/)).toBeNull();
    cleanup();
    renderCard(<DNSQueryRateCard />);
    expect(await screen.findByText(/couldn't be loaded/)).toBeTruthy();
    expect(screen.queryByText(/Your role/)).toBeNull();
  });

  it("a 403 reads as missing access", async () => {
    fail.err = { response: { status: 403, data: { detail: "Forbidden" } } };
    renderCard(<DHCPTrafficCard />);
    expect(await screen.findByText(/Your role may not include/)).toBeTruthy();
  });
});
