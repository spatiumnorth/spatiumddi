/**
 * @vitest-environment jsdom
 *
 * #3046 — the DHCP and DNS server inspectors' "Last sync" card read
 * `last_sync_at`, which no agent-managed server sets (and nothing sets for
 * any DNS server), so a server whose config is applied read the same empty
 * placeholder as one that never synced.
 */
import { act, cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const stubs = Object.fromEntries(
    Object.entries(actual)
      .filter(([name, v]) => name.endsWith("Api") && typeof v === "object")
      .map(([name]) => [
        name,
        new Proxy(
          {},
          {
            get: (_t, method) => {
              if (typeof method === "symbol") return undefined;
              if (name === "authApi" && method === "myPermissions")
                return () =>
                  Promise.resolve({ is_superadmin: true, grants: [] });
              return pending;
            },
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

import { ServerDetailModal as DhcpServerDetailModal } from "./dhcp/ServerDetailModal";
import { ServerDetailModal as DnsServerDetailModal } from "./dns/ServerDetailModal";
import type { DHCPServer, DNSServer } from "@/lib/api";

const NOW = new Date("2026-10-29T20:40:00.000Z");
const FIVE_MIN_AGO = "2026-10-29T20:35:00.000Z";
const TWO_DAYS_AGO = "2026-10-27T20:40:00.000Z";

const COMMON = {
  id: "s1",
  group_id: "g1",
  server_group_id: "g1",
  name: "ddipg-seed",
  roles: [],
  host: "192.0.2.53",
  port: 53,
  is_primary: true,
  is_enabled: true,
  status: "active",
  last_sync_at: null,
  config_apply_status: null,
  config_apply_at: null,
};

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

async function show(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(50);
  });
}

/** The value under an InfoCard's label (the label's next sibling). */
function card(label: string): string | null {
  const el = screen
    .queryAllByText(label, { exact: true })
    .find((e) => e.className.includes("uppercase"));
  return el?.nextElementSibling?.textContent ?? null;
}

describe("DHCP server inspector (#3046)", () => {
  it("shows a Kea server's apply time, not an empty Last sync", async () => {
    await show(
      <DhcpServerDetailModal
        server={
          {
            ...COMMON,
            driver: "kea",
            config_apply_status: "ok",
            config_apply_at: FIVE_MIN_AGO,
          } as unknown as DHCPServer
        }
        onClose={() => {}}
      />,
    );
    expect(card("Config applied")).toBe("5m ago");
    expect(card("Last sync")).toBeNull();
  });

  it("lets a fresher apply report beat a stale last_sync_at", async () => {
    await show(
      <DhcpServerDetailModal
        server={
          {
            ...COMMON,
            driver: "kea",
            last_sync_at: TWO_DAYS_AGO,
            config_apply_status: "ok",
            config_apply_at: FIVE_MIN_AGO,
          } as unknown as DHCPServer
        }
        onClose={() => {}}
      />,
    );
    expect(card("Config applied")).toBe("5m ago");
  });

  it("keeps the placeholder for a server that never synced", async () => {
    await show(
      <DhcpServerDetailModal
        server={{ ...COMMON, driver: "kea" } as unknown as DHCPServer}
        onClose={() => {}}
      />,
    );
    expect(card("Last sync")).toBe("—");
  });
});

describe("DNS server inspector (#3046)", () => {
  it("shows a BIND9 server's apply time, not an empty Last sync", async () => {
    await show(
      <DnsServerDetailModal
        server={
          {
            ...COMMON,
            driver: "bind9",
            is_agentless: false,
            config_apply_status: "ok",
            config_apply_at: FIVE_MIN_AGO,
          } as unknown as DNSServer
        }
        onClose={() => {}}
      />,
    );
    expect(card("Config applied")).toBe("5m ago");
    expect(card("Last sync")).toBeNull();
  });

  it("keeps the placeholder for an agent that never reported", async () => {
    await show(
      <DnsServerDetailModal
        server={
          {
            ...COMMON,
            driver: "bind9",
            is_agentless: false,
          } as unknown as DNSServer
        }
        onClose={() => {}}
      />,
    );
    expect(card("Last sync")).toBe("—");
  });

  it("says an agentless server records no sync, not a bare dash", async () => {
    await show(
      <DnsServerDetailModal
        server={
          {
            ...COMMON,
            driver: "windows_dns",
            is_agentless: true,
          } as unknown as DNSServer
        }
        onClose={() => {}}
      />,
    );
    expect(card("Last sync")).toBe("Not recorded for agentless servers");
  });
});
