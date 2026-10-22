/**
 * @vitest-environment jsdom
 *
 * With ``ipam.nat`` off, NAT mappings leave the Dashboard and the IPAM
 * detail views, and nothing calls ``/ipam/nat-mappings`` — which answers 404
 * while the module is off (#2100).
 *
 * Same harness as ``dhcp-off-2130.test.tsx``: the API objects are recorders,
 * so the assertions are on calls actually made. ``ready: false`` is its own
 * case because ``enabled()`` answers true while the module set loads.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import type { IPAddress, Subnet } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
const calls: string[] = [];

const mods = { ready: true, off: new Set<string>() };

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
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : (...args: unknown[]) => {
                    calls.push(`${name}.${method}`);
                    return (answers[name]?.[method] ?? pending)(...args);
                  },
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    modules: [],
    ready: mods.ready,
    isLoading: !mods.ready,
    isError: false,
    refetch: () => {},
    enabled: (id: string) => !mods.off.has(id),
  }),
}));

const { DashboardPage } = await import("./DashboardPage");
const { SubnetDetail } = await import("./ipam/IPAMPage");
const { IPDetailModal } = await import("./ipam/IPDetailModal");
const { NATPage } = await import("./ipam/NATPage");

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

const natCalls = () => calls.filter((c) => c.startsWith("natApi."));

function open(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const natOff = () => {
  mods.off = new Set(["ipam.nat"]);
};

beforeEach(() => {
  mods.ready = true;
  mods.off = new Set();
  calls.length = 0;
  localStorage.clear();
  sessionStorage.clear();
});

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const STAMP = "2026-10-02T00:00:00Z";

function address(over: Partial<IPAddress> = {}): IPAddress {
  return {
    id: "ip-1",
    subnet_id: "sub-1",
    address: "10.85.20.41",
    status: "allocated",
    role: null,
    hostname: "web01",
    fqdn: null,
    description: "",
    mac_address: null,
    tags: {},
    custom_fields: {},
    created_at: STAMP,
    modified_at: STAMP,
    nat_mapping_count: 2,
    ...over,
  };
}

// ── Dashboard ────────────────────────────────────────────────────────────────

describe("Dashboard NAT card", () => {
  beforeEach(() => localStorage.setItem("dashboard-tab", "ipam"));

  it("reads the NAT count and shows the card while NAT is on (control)", async () => {
    answer("natApi", "list", () =>
      Promise.resolve({ total: 3, page: 1, per_page: 1, items: [] }),
    );
    open(<DashboardPage />);
    await waitFor(() => expect(natCalls()).toContain("natApi.list"));
    expect(await screen.findByText("NAT mappings")).toBeTruthy();
  });

  it("reads nothing and shows no card while NAT is off", async () => {
    natOff();
    open(<DashboardPage />);
    await screen.findByText(/Dashboard/i);
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByText("NAT mappings")).toBeNull();
    expect(natCalls()).toEqual([]);
  });

  it("reads nothing before the module set has loaded", async () => {
    mods.ready = false;
    open(<DashboardPage />);
    await screen.findByText(/Dashboard/i);
    await new Promise((r) => setTimeout(r, 20));
    expect(natCalls()).toEqual([]);
  });
});

// ── IPAM: subnet detail ──────────────────────────────────────────────────────

describe("Subnet detail", () => {
  function subnetDetail() {
    answer("ipamApi", "listAddresses", () => Promise.resolve([address()]));
    answer("dhcpApi", "listScopesBySubnet", () => Promise.resolve([]));
    const subnet = {
      id: "sub-1",
      space_id: "sp-1",
      block_id: "blk-1",
      network: "10.85.20.0/24",
      name: "lab",
      total_ips: 254,
      allocated_ips: 1,
      utilization_percent: 1,
      dns_group_ids: [],
    } as unknown as Subnet;
    open(<SubnetDetail subnet={subnet} onSubnetEdited={() => {}} />);
  }

  it("has the NAT tab and the per-address NAT badge while NAT is on (control)", async () => {
    subnetDetail();
    expect(await screen.findByText("NAT 2")).toBeTruthy();
    expect(screen.getByRole("button", { name: "NAT" })).toBeTruthy();
  });

  it("has neither while NAT is off", async () => {
    natOff();
    subnetDetail();
    await screen.findByText("web01");
    expect(screen.queryByText("NAT 2")).toBeNull();
    expect(screen.queryByRole("button", { name: "NAT" })).toBeNull();
    expect(natCalls()).toEqual([]);
  });

  it("has neither before the module set has loaded", async () => {
    mods.ready = false;
    subnetDetail();
    await screen.findByText("web01");
    expect(screen.queryByText("NAT 2")).toBeNull();
    expect(screen.queryByRole("button", { name: "NAT" })).toBeNull();
  });
});

// ── IPAM: IP detail ──────────────────────────────────────────────────────────

describe("IP detail", () => {
  function ipDetail() {
    open(
      <IPDetailModal
        address={address()}
        canEdit={false}
        onClose={() => {}}
        onEdit={() => {}}
        onScan={() => {}}
      />,
    );
  }

  it("shows the NAT badge while NAT is on (control)", async () => {
    ipDetail();
    expect(await screen.findByText("NAT 2")).toBeTruthy();
  });

  it("hides it while NAT is off", async () => {
    natOff();
    ipDetail();
    await screen.findByText("10.85.20.41");
    expect(screen.queryByText("NAT 2")).toBeNull();
    expect(natCalls()).toEqual([]);
  });
});

// ── NAT Mappings page ────────────────────────────────────────────────────────

describe("NAT Mappings page", () => {
  it("lists mappings while NAT is on (control)", async () => {
    answer("natApi", "list", () =>
      Promise.resolve({ total: 0, page: 1, per_page: 50, items: [] }),
    );
    open(<NATPage />);
    await waitFor(() => expect(natCalls()).toContain("natApi.list"));
    expect(screen.queryByText(/NAT mappings are turned off/)).toBeNull();
  });

  it("says it is off, offers no create, and calls nothing while NAT is off", async () => {
    // Reached by bookmark, or left open after deleting the last mapping on
    // an install that never set the toggle.
    natOff();
    open(<NATPage />);
    expect(await screen.findByText(/NAT mappings are turned off/)).toBeTruthy();
    expect(screen.queryByText("New mapping")).toBeNull();
    await new Promise((r) => setTimeout(r, 20));
    expect(natCalls()).toEqual([]);
  });

  it("calls nothing before the module set has loaded", async () => {
    mods.ready = false;
    open(<NATPage />);
    await new Promise((r) => setTimeout(r, 20));
    expect(natCalls()).toEqual([]);
  });
});
