/**
 * @vitest-environment jsdom
 *
 * #4193 — agents report their actual memory; the server list shows used
 * against limit (amber over 80 %), the modal shows the breakdown and a
 * sparkline, and the blocklists banner sets each server's real named RSS
 * beside the estimate. An agent that never reported reads "—", not 0.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import type { DNSMemoryEstimate } from "@/lib/api";

const getMemoryEstimate = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    dnsApi: { ...actual.dnsApi, getMemoryEstimate },
  };
});

const { AgentMemoryCell } = await import("./AgentMemoryCell");
const { AgentMemoryPanel } = await import("./AgentMemoryPanel");
const { DnsMemoryBanner } = await import("@/pages/dns/DnsMemoryBanner");
const { memoryUsage } = await import("@/lib/agent-memory");

const MIB = 1024 * 1024;

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

describe("memoryUsage", () => {
  it("is amber only above 80 % of the limit", () => {
    const at = (used: number) =>
      memoryUsage({ used_bytes: used * MIB, limit_bytes: 1000 * MIB });
    expect(at(800).warn).toBe(false);
    expect(at(801).warn).toBe(true);
    expect(at(500).percent).toBe(50);
  });

  it("reads — when unreported and the bare figure when there is no limit", () => {
    expect(memoryUsage(null).text).toBe("—");
    expect(memoryUsage({ limit_bytes: 5 }).text).toBe("—");
    const noLimit = memoryUsage({ used_bytes: 2 * MIB });
    expect(noLimit.text).toBe("2.0 MB");
    expect(noLimit.warn).toBe(false);
  });
});

describe("server list Memory column", () => {
  it("shows used / limit and warns over 80 %", () => {
    render(
      <AgentMemoryCell
        server={{
          memory_status: { used_bytes: 900 * MIB, limit_bytes: 1000 * MIB },
        }}
      />,
    );
    const cell = screen.getByTestId("agent-memory-cell");
    expect(cell.textContent).toContain("900.0 MB / 1000.0 MB");
    expect(cell.className).toContain("amber");
  });

  it("shows — for an older agent that sent no block", () => {
    render(<AgentMemoryCell server={{ memory_status: null }} />);
    const cell = screen.getByTestId("agent-memory-cell");
    expect(cell.textContent).toContain("—");
    expect(cell.className).not.toContain("amber");
  });
});

describe("server modal memory panel", () => {
  const status = {
    used_bytes: 700 * MIB,
    peak_bytes: 900 * MIB,
    limit_bytes: 1024 * MIB,
    daemon_rss_bytes: 600 * MIB,
    agent_rss_bytes: 80 * MIB,
  };

  it("shows container used / peak / limit, daemon + agent RSS and a sparkline", async () => {
    const fetchHistory = vi.fn().mockResolvedValue({
      server_id: "s1",
      hours: 6,
      points: [1, 2, 3].map((n) => ({
        ts: `2026-11-14T10:0${n}:00Z`,
        used_bytes: n * 100 * MIB,
        peak_bytes: null,
        daemon_rss_bytes: null,
        agent_rss_bytes: null,
      })),
    });
    wrap(
      <AgentMemoryPanel
        serverId="s1"
        status={status}
        daemonLabel="named"
        fetchHistory={fetchHistory}
        queryKeyPrefix="t"
      />,
    );
    const panel = screen.getByTestId("agent-memory-panel");
    expect(panel.textContent).toContain("700.0 MB");
    expect(panel.textContent).toContain("900.0 MB");
    expect(panel.textContent).toContain("1.0 GB");
    expect(panel.textContent).toContain("named RSS");
    expect(panel.textContent).toContain("600.0 MB");
    expect(panel.textContent).toContain("80.0 MB");
    await waitFor(() => screen.getByTestId("memory-sparkline"));
  });

  it("says so, with no sparkline, for an agent that does not report", async () => {
    const fetchHistory = vi
      .fn()
      .mockResolvedValue({ server_id: "s1", hours: 6, points: [] });
    wrap(
      <AgentMemoryPanel
        serverId="s1"
        status={null}
        daemonLabel="Kea"
        fetchHistory={fetchHistory}
        queryKeyPrefix="t2"
      />,
    );
    expect(screen.getByTestId("agent-memory-panel").textContent).toContain(
      "Not reported by this agent",
    );
    await waitFor(() => expect(fetchHistory).toHaveBeenCalled());
    expect(screen.queryByTestId("memory-sparkline")).toBeNull();
  });
});

describe("server modal memory panel after the report is cleared", () => {
  it("draws no sparkline from old history when nothing is currently reported", async () => {
    const fetchHistory = vi.fn().mockResolvedValue({
      server_id: "s1",
      hours: 6,
      points: [1, 2, 3].map((n) => ({
        ts: `2026-11-14T10:0${n}:00Z`,
        used_bytes: n * 100 * MIB,
        peak_bytes: null,
        daemon_rss_bytes: null,
        agent_rss_bytes: null,
      })),
    });
    wrap(
      <AgentMemoryPanel
        serverId="s1"
        status={null}
        daemonLabel="named"
        fetchHistory={fetchHistory}
        queryKeyPrefix="t3"
      />,
    );
    await waitFor(() => expect(fetchHistory).toHaveBeenCalled());
    // let the query resolve so the history is in hand before asserting
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.getByTestId("agent-memory-panel").textContent).toContain(
      "Not reported",
    );
    expect(screen.queryByTestId("memory-sparkline")).toBeNull();
  });
});

describe("blocklists page banner", () => {
  function est(servers: DNSMemoryEstimate["servers"]): DNSMemoryEstimate {
    return {
      group_id: "g1",
      estimated_bytes: 500 * MIB,
      limit_bytes: 1024 * MIB,
      limit_source: "agent",
      limit_server: "ns1",
      unknown_limit_servers: [],
      percent: 48.8,
      warn: false,
      message: null,
      baseline_bytes: 400 * MIB,
      zone_records_loaded: 0,
      zone_bytes: 0,
      rpz_bytes: 0,
      rpz: [],
      views: ["default"],
      servers,
    };
  }

  it("sets each server's actual named RSS beside the estimate, even when not warning", async () => {
    getMemoryEstimate.mockResolvedValue(
      est([
        {
          name: "ns1",
          daemon_rss_bytes: 612 * MIB,
          used_bytes: 700 * MIB,
          peak_bytes: null,
          limit_bytes: 1024 * MIB,
          reported_at: null,
        },
        {
          name: "ns2-old",
          daemon_rss_bytes: null,
          used_bytes: null,
          peak_bytes: null,
          limit_bytes: null,
          reported_at: null,
        },
      ]),
    );
    wrap(<DnsMemoryBanner groupId="g1" />);
    const box = await screen.findByTestId("dns-memory-observed");
    expect(box.textContent).toContain("estimate is about 500 MiB");
    expect(box.textContent).toContain("ns1: named 612 MiB");
    expect(box.textContent).toContain("container 700 MiB / 1.0 GiB");
    expect(box.textContent).toContain("ns2-old: named —, container —");
  });

  it("shows nothing extra when no server has reported", async () => {
    getMemoryEstimate.mockResolvedValue(
      est([
        {
          name: "ns1",
          daemon_rss_bytes: null,
          used_bytes: null,
          peak_bytes: null,
          limit_bytes: null,
          reported_at: null,
        },
      ]),
    );
    wrap(<DnsMemoryBanner groupId="g1" />);
    await waitFor(() => expect(getMemoryEstimate).toHaveBeenCalled());
    expect(screen.queryByTestId("dns-memory-observed")).toBeNull();
  });
});
