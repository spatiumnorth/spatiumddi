/**
 * @vitest-environment jsdom
 *
 * With ``core.dhcp`` off, the rest of the UI stops showing DHCP and stops
 * calling ``/dhcp/*`` (#2130).
 *
 * The API objects are replaced by recorders, so each test asserts on the
 * calls that were actually made, not on a prop. ``ready: false`` is its own
 * case: ``enabled()`` answers true while the module set is loading, which is
 * how a hard reload used to fire a gated read once and 404.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import type { IPAddress, Subnet } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
/** Every ``<api>.<method>`` call made, in order. */
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

const { LogsPage } = await import("./LogsPage");
const { SettingsPage } = await import("./SettingsPage");
const { DashboardPage } = await import("./DashboardPage");
const { ImportPage } = await import("./admin/ImportPage");
const { IPAMTemplatesPage } = await import("./admin/IPAMTemplatesPage");
const { CreateSubnetModal, EditAddressModal, SubnetDetail } =
  await import("./ipam/IPAMPage");

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

function dhcpCalls() {
  return calls.filter((c) => /dhcp/i.test(c));
}

function open(ui: ReactNode, route = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function dhcpOff() {
  // dhcp.import requires core.dhcp, which the real resolver folds in.
  mods.off = new Set(["core.dhcp", "dhcp.import"]);
}

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
    ...over,
  };
}

// ── Logs ─────────────────────────────────────────────────────────────────────

describe("Logs tabs", () => {
  function logs(route = "/logs") {
    answer("logsApi", "listSources", () => Promise.resolve([]));
    answer("logsApi", "listAgentSources", () =>
      Promise.resolve([
        {
          server_id: "s1",
          server_name: "ns1",
          server_kind: "dns",
          driver: "bind9",
          host: "10.0.0.1",
        },
      ]),
    );
    open(<LogsPage />, route);
  }

  it("shows the DHCP tabs while DHCP is on (control)", async () => {
    logs();
    expect(await screen.findByText("DHCP Activity")).toBeTruthy();
    expect(screen.getByText("DHCP Audit")).toBeTruthy();
  });

  it("drops both DHCP tabs while DHCP is off", async () => {
    dhcpOff();
    logs();
    expect(await screen.findByText("DNS Queries")).toBeTruthy();
    expect(screen.queryByText("DHCP Activity")).toBeNull();
    expect(screen.queryByText("DHCP Audit")).toBeNull();
  });

  it.each(["dhcp-activity", "audit"])(
    "?tab=%s falls back to a tab that exists, and reads no DHCP log",
    async (tab) => {
      dhcpOff();
      logs(`/logs?tab=${tab}`);
      await screen.findByText("DNS Queries");
      expect(screen.queryByText("DHCP Activity")).toBeNull();
      expect(dhcpCalls()).toEqual([]);
    },
  );

  it("does not show a DHCP tab before the module set has loaded", async () => {
    mods.ready = false;
    logs("/logs?tab=dhcp-activity");
    await screen.findByText("DNS Queries");
    expect(screen.queryByText("DHCP Activity")).toBeNull();
    expect(dhcpCalls()).toEqual([]);
    // Nor does it mount DNS Queries in the meantime: the deep link may be
    // valid once the module set says DHCP is on.
    expect(calls).not.toContain("logsApi.dnsQueries");
  });

  it("?tab=dhcp-activity opens DHCP Activity while DHCP is on (control)", async () => {
    logs("/logs?tab=dhcp-activity");
    // The fixture has no DHCP agent, so the DHCP Activity tab shows its
    // empty state: proof the deep link landed there, not on DNS Queries.
    expect(
      await screen.findByText("No DHCP servers using a SpatiumDDI agent."),
    ).toBeTruthy();
    expect(calls).not.toContain("logsApi.dnsQueries");
  });
});

// ── Settings ─────────────────────────────────────────────────────────────────

describe("Settings sections", () => {
  function settings() {
    answer("authApi", "me", () => Promise.resolve({ is_superadmin: true }));
    answer("settingsApi", "get", () => Promise.resolve({}));
    answer("settingsApi", "getDefaults", () => Promise.resolve({}));
    open(<SettingsPage />);
  }

  it("lists the DHCP sections while DHCP is on (control)", async () => {
    settings();
    expect(await screen.findByText("DHCP Defaults")).toBeTruthy();
    expect(screen.getByText("DHCP Lease Sync")).toBeTruthy();
    expect(screen.getByText("Device Profiling")).toBeTruthy();
  });

  it("hides them while DHCP is off, but keeps the agent bootstrap keys", async () => {
    dhcpOff();
    settings();
    expect(await screen.findByText("Agent bootstrap keys")).toBeTruthy();
    expect(screen.queryByText("DHCP Defaults")).toBeNull();
    expect(screen.queryByText("DHCP Lease Sync")).toBeNull();
    expect(screen.queryByText("Device Profiling")).toBeNull();
  });

  it("hides them until the module set has loaded", async () => {
    mods.ready = false;
    settings();
    expect(await screen.findByText("Agent bootstrap keys")).toBeTruthy();
    expect(screen.queryByText("DHCP Defaults")).toBeNull();
  });
});

// ── Dashboard ────────────────────────────────────────────────────────────────

describe("Dashboard on a hard reload with the DHCP tab persisted", () => {
  beforeEach(() => localStorage.setItem("dashboard-tab", "dhcp"));

  it("reads no DHCP data before the module set has loaded", async () => {
    mods.ready = false;
    open(<DashboardPage />);
    await screen.findByText(/Dashboard/i);
    expect(dhcpCalls()).toEqual([]);
    // The persisted choice is kept, not overwritten, while it is unknown.
    expect(localStorage.getItem("dashboard-tab")).toBe("dhcp");
  });

  it("falls back to Overview and reads no DHCP data when DHCP is off", async () => {
    dhcpOff();
    open(<DashboardPage />);
    await waitFor(() =>
      expect(localStorage.getItem("dashboard-tab")).toBe("overview"),
    );
    expect(dhcpCalls()).toEqual([]);
  });

  it("reads the fleet pool occupancy while DHCP is on (control)", async () => {
    open(<DashboardPage />);
    await waitFor(() => expect(calls).toContain("dhcpApi.fleetPoolOccupancy"));
  });
});

// ── Import ───────────────────────────────────────────────────────────────────

describe("Import", () => {
  it("does not mount the default DHCP importer before the modules load", async () => {
    mods.ready = false;
    open(<ImportPage />);
    await new Promise((r) => setTimeout(r, 20));
    expect(dhcpCalls()).toEqual([]);
    expect(
      screen.queryByText("No importers are enabled", { exact: false }),
    ).toBeNull();
  });

  it("offers no DHCP importer, and reads no DHCP data, when DHCP is off", async () => {
    dhcpOff();
    open(<ImportPage />);
    expect(await screen.findByText("DNS")).toBeTruthy();
    expect(screen.queryByText("DHCP")).toBeNull();
    await new Promise((r) => setTimeout(r, 20));
    expect(dhcpCalls()).toEqual([]);
  });

  it("opens on the DHCP importer while DHCP is on (control)", async () => {
    open(<ImportPage />);
    await waitFor(() => expect(calls).toContain("dhcpApi.listGroups"));
  });
});

// ── Admin → IPAM Templates ───────────────────────────────────────────────────

describe("IPAM Templates", () => {
  function templates() {
    answer("ipamTemplatesApi", "list", () => Promise.resolve([]));
    open(<IPAMTemplatesPage />);
  }

  it("has a DHCP group column while DHCP is on (control)", async () => {
    templates();
    expect(await screen.findByText("DHCP group")).toBeTruthy();
  });

  it("drops the column and the group read while DHCP is off", async () => {
    dhcpOff();
    templates();
    expect(await screen.findByText("DNS group")).toBeTruthy();
    expect(screen.queryByText("DHCP group")).toBeNull();
    expect(dhcpCalls()).toEqual([]);
  });
});

// ── IPAM: dialogs ────────────────────────────────────────────────────────────

describe("New Subnet dialog", () => {
  function newSubnet() {
    answer("ipamApi", "listBlocks", () => Promise.resolve([]));
    answer("ipamApi", "listTemplates", () => Promise.resolve([]));
    open(<CreateSubnetModal spaceId="sp-1" onClose={() => {}} />);
  }

  it("has DHCP and DDNS tabs while DHCP is on (control)", async () => {
    newSubnet();
    expect(await screen.findByRole("button", { name: "DHCP" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "DDNS" })).toBeTruthy();
  });

  it("has neither while DHCP is off, nor device profiling under Advanced", async () => {
    dhcpOff();
    newSubnet();
    await screen.findByRole("button", { name: "General" });
    expect(screen.queryByRole("button", { name: "DHCP" })).toBeNull();
    expect(screen.queryByRole("button", { name: "DDNS" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Advanced" }));
    expect(screen.queryByText(/Device profiling/)).toBeNull();
    expect(dhcpCalls()).toEqual([]);
  });

  it("has neither before the module set has loaded", async () => {
    mods.ready = false;
    newSubnet();
    await screen.findByRole("button", { name: "General" });
    expect(screen.queryByRole("button", { name: "DHCP" })).toBeNull();
    expect(dhcpCalls()).toEqual([]);
  });
});

describe("Edit IP status choices", () => {
  async function options(status: string) {
    // Edit address reads its row fresh on open (#3077).
    const row = address({ status });
    answer("ipamApi", "getAddress", () => Promise.resolve(row));
    open(<EditAddressModal address={row} onClose={() => {}} />);
    const select = (await screen.findByText("Status", { selector: "label" }))
      .nextElementSibling as HTMLSelectElement;
    return { select, values: [...select.options].map((o) => o.value) };
  }

  it("offers dhcp and static_dhcp while DHCP is on (control)", async () => {
    const { values } = await options("allocated");
    expect(values).toEqual(expect.arrayContaining(["dhcp", "static_dhcp"]));
  });

  it("does not offer them as choices while DHCP is off", async () => {
    dhcpOff();
    const { values } = await options("allocated");
    expect(values).not.toContain("dhcp");
    expect(values).not.toContain("static_dhcp");
    expect(values).toContain("allocated");
  });

  it("a stored static_dhcp address shows no 'create a scope' notice while DHCP is off", async () => {
    dhcpOff();
    await options("static_dhcp");
    expect(
      screen.queryByText("No DHCP scope exists", { exact: false }),
    ).toBeNull();
    expect(dhcpCalls()).toEqual([]);
  });

  it.each(["dhcp", "static_dhcp"])(
    "an address that already is %s still shows it, and keeps it on save",
    async (status) => {
      dhcpOff();
      const updateAddress = vi.fn((..._a: unknown[]) =>
        Promise.resolve(address({ status })),
      );
      answer("ipamApi", "updateAddress", updateAddress);
      const { select } = await options(status);
      expect(select.value).toBe(status);
      // An edit sends only what changed (#3091), so change the description:
      // the stored status is not in the body, which is what keeps it.
      fireEvent.change(
        screen.getByText("Description", { selector: "label" })
          .nextElementSibling as HTMLInputElement,
        { target: { value: "edited" } },
      );
      fireEvent.click(screen.getByRole("button", { name: "Save" }));
      await waitFor(() => expect(updateAddress).toHaveBeenCalledTimes(1));
      expect(updateAddress.mock.calls[0][1]).toMatchObject({
        description: "edited",
      });
      expect(updateAddress.mock.calls[0][1]).not.toHaveProperty("status");
    },
  );
});

// ── IPAM: subnet detail ──────────────────────────────────────────────────────

describe("Subnet detail", () => {
  function subnetDetail() {
    answer("ipamApi", "listAddresses", () =>
      Promise.resolve([address({ id: "ip-1" })]),
    );
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

  it("has the DHCP Pools tab and the DHCP Pool column while DHCP is on (control)", async () => {
    subnetDetail();
    expect(await screen.findByText("DHCP Pools")).toBeTruthy();
    expect(await screen.findByText("DHCP Pool")).toBeTruthy();
    expect(calls).toContain("dhcpApi.listScopesBySubnet");
  });

  it("has neither, and reads no DHCP data, while DHCP is off", async () => {
    dhcpOff();
    subnetDetail();
    expect(await screen.findByText("IP Addresses")).toBeTruthy();
    await screen.findByText("hostname");
    expect(screen.queryByText("DHCP Pools")).toBeNull();
    expect(screen.queryByText("DHCP Pool")).toBeNull();
    expect(dhcpCalls()).toEqual([]);
  });

  it("reads no DHCP data before the module set has loaded", async () => {
    mods.ready = false;
    subnetDetail();
    await screen.findByText("IP Addresses");
    expect(screen.queryByText("DHCP Pools")).toBeNull();
    expect(dhcpCalls()).toEqual([]);
  });
});
