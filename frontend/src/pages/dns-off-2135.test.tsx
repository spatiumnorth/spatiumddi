/**
 * @vitest-environment jsdom
 *
 * With ``core.dns`` off, the rest of the UI stops showing DNS and stops
 * calling ``/dns/*`` (#2135) — the DNS counterpart of ``dhcp-off-2130``.
 *
 * The API objects are replaced by recorders, so each test asserts on the
 * calls that were actually made, not on a prop. ``ready: false`` is its own
 * case: ``enabled()`` answers true while the module set is loading, which is
 * how a hard reload used to fire a gated read once and 404. Every surface has
 * a DNS-on control, so a test that passes cannot be one that never rendered
 * the thing it says is absent.
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
const { IPAMTemplatesPage } = await import("./admin/IPAMTemplatesPage");
const { ApplianceRoleAssignmentSection } = await import("./appliance/FleetTab");
const {
  AddAddressModal,
  CreateSubnetModal,
  EditAddressModal,
  EditSubnetModal,
  SubnetDetail,
} = await import("./ipam/IPAMPage");

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

/**
 * Any recorded call to a DNS endpoint: the DNS APIs, the IPAM DNS-sync reads
 * and the DNS query log. (``ipamApi.getEffectiveSubnetDns`` is an IPAM read
 * about inheritance, not a DNS call, and stays.)
 */
function dnsCalls() {
  return calls.filter((c) =>
    /^dns[A-Za-z]*Api\.|^ipamApi\.dnsSync|^logsApi\.dnsQueries/.test(c),
  );
}

function open(ui: ReactNode, route = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function dnsOff() {
  // Everything that requires core.dns, which the real resolver folds in.
  mods.off = new Set([
    "core.dns",
    "dns.import",
    "dns.dynamic_update_acl",
    "security.dns_threat",
    "security.dnsbl",
  ]);
}

function bothOff() {
  dnsOff();
  mods.off.add("core.dhcp");
  mods.off.add("dhcp.import");
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
        {
          server_id: "s2",
          server_name: "dhcp1",
          server_kind: "dhcp",
          driver: "kea",
          host: "10.0.0.2",
        },
      ]),
    );
    open(<LogsPage />, route);
  }

  it("shows both DNS tabs while DNS is on (control)", async () => {
    logs();
    expect(await screen.findByText("DNS Queries")).toBeTruthy();
    expect(screen.getByText("DNS Threat")).toBeTruthy();
    await waitFor(() => expect(calls).toContain("logsApi.dnsQueries"));
  });

  it("drops both DNS tabs and lands on the DHCP tab while DNS is off", async () => {
    dnsOff();
    logs();
    expect(await screen.findByText("DHCP Activity")).toBeTruthy();
    expect(screen.queryByText("DNS Queries")).toBeNull();
    expect(screen.queryByText("DNS Threat")).toBeNull();
    expect(calls).not.toContain("logsApi.dnsQueries");
    expect(calls).not.toContain("dnsThreatApi.summary");
  });

  it.each(["dns-queries", "dns-threat"])(
    "?tab=%s falls back to a tab that exists, and reads no DNS data",
    async (tab) => {
      dnsOff();
      logs(`/logs?tab=${tab}`);
      await screen.findByText("DHCP Activity");
      expect(screen.queryByText("DNS Queries")).toBeNull();
      expect(dnsCalls()).toEqual([]);
    },
  );

  it("still has a valid tab with DNS and DHCP both off: the Event Log", async () => {
    bothOff();
    logs();
    const tab = (name: RegExp) => screen.queryByRole("button", { name });
    await screen.findByRole("button", { name: /^Event Log/ });
    expect(tab(/^DNS Queries/)).toBeNull();
    expect(tab(/^DNS Threat/)).toBeNull();
    expect(tab(/^DHCP Activity/)).toBeNull();
    expect(tab(/^DHCP Audit/)).toBeNull();
    // The Event Log is the one tab mounted: its own source query ran.
    await waitFor(() => expect(calls).toContain("logsApi.listSources"));
    expect(calls).not.toContain("logsApi.dnsQueries");
    expect(dnsCalls()).toEqual([]);
  });

  it.each(["/logs", "/logs?tab=dns-queries", "/logs?tab=dns-threat"])(
    "%s reads no DNS data before the module set has loaded",
    async (route) => {
      mods.ready = false;
      logs(route);
      await screen.findByText("Event Log");
      expect(calls).not.toContain("logsApi.dnsQueries");
      expect(dnsCalls()).toEqual([]);
    },
  );
});

describe("Logs tab highlight on a hard reload", () => {
  // The bodies wait for the module set; the highlighted tab must not flick
  // to the Event Log meanwhile and back again once DNS turns out to be on.
  const isActive = (el: HTMLElement) =>
    (el.closest("button")?.className ?? "").includes("border-primary");

  it.each([
    ["/logs", "DNS Queries"],
    ["/logs?tab=dns-threat", "DNS Threat"],
  ])(
    "%s highlights the tab it will land on while loading",
    async (route, name) => {
      mods.ready = false;
      answer("logsApi", "listSources", () => Promise.resolve([]));
      // At least one source, or the page renders its empty state instead.
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
      expect(isActive(await screen.findByText(name))).toBe(true);
      expect(isActive(screen.getByText("Event Log"))).toBe(false);
      expect(dnsCalls()).toEqual([]);
    },
  );
});

// ── Stored DNS values survive a save with DNS off ────────────────────────────

describe("Saving with DNS off keeps the stored DNS linkage", () => {
  it("Edit IP omits dns_zone_id, so the forward / extra zones stay", async () => {
    dnsOff();
    let body: Record<string, unknown> | undefined;
    answer("ipamApi", "updateAddress", (_id, b) => {
      body = b as Record<string, unknown>;
      return Promise.resolve({ ...address(), dhcp_static_warning: null });
    });
    answer("ipamApi", "getEffectiveSubnetDns", () =>
      Promise.resolve({
        dns_group_ids: ["g1"],
        dns_zone_id: "z1",
        dns_additional_zone_ids: ["z2"],
      }),
    );
    const row = address({
      forward_zone_id: "z1",
      extra_zone_ids: ["z2"],
    } as Partial<IPAddress>);
    // Edit address reads its row fresh on open (#3077).
    answer("ipamApi", "getAddress", () => Promise.resolve(row));
    open(<EditAddressModal address={row} onClose={() => {}} />);
    await screen.findByText("Hostname");
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByText("DNS Zone")).toBeNull();
    expect(screen.queryByText("DNS Aliases")).toBeNull();
    // An edit sends only what changed (#3091), so change the hostname: the
    // zone must still be left out of the body.
    fireEvent.change(screen.getByDisplayValue("web01"), {
      target: { value: "web02" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(body).toBeDefined());
    expect(body?.hostname).toBe("web02");
    // ``undefined`` is dropped on the wire, so the backend keeps the zone.
    expect(body?.dns_zone_id).toBeUndefined();
    expect(body).not.toHaveProperty("extra_zone_ids");
    expect(body).not.toHaveProperty("aliases");
    expect(dnsCalls()).toEqual([]);
  });

  it("Edit Subnet leaves the stored DNS and DDNS settings alone", async () => {
    dnsOff();
    let body: Record<string, unknown> | undefined;
    answer("ipamApi", "updateSubnet", (_id, b) => {
      body = b as Record<string, unknown>;
      return Promise.resolve({});
    });
    const subnet = {
      id: "sub-1",
      space_id: "sp-1",
      block_id: "blk-1",
      network: "10.85.20.0/24",
      name: "lab",
      description: "",
      status: "active",
      custom_fields: {},
      dns_inherit_settings: false,
      dns_group_ids: ["g1"],
      dns_zone_id: "z1",
      dns_additional_zone_ids: ["z2"],
      dns_split_horizon: true,
      // #2475 — a subnet carrying its own DDNS has opted out of inheriting;
      // while inheriting the dialog sends only the flag.
      ddns_inherit_settings: false,
      ddns_enabled: true,
      ddns_hostname_policy: "client_provided",
      ddns_domain_override: "dyn.example.",
      ddns_ttl: 300,
    } as unknown as Subnet;
    answer("ipamApi", "getSubnet", () => Promise.resolve(subnet));
    open(<EditSubnetModal subnet={subnet} onClose={() => {}} />);
    await screen.findByRole("button", { name: "General" });
    expect(screen.queryByRole("button", { name: "DNS" })).toBeNull();
    expect(screen.queryByRole("button", { name: "DDNS" })).toBeNull();
    // An edit sends only what changed (#3269): change the name, and the
    // stored DNS / DDNS linkage must not ride along (or be cleared).
    fireEvent.change(screen.getByDisplayValue("lab"), {
      target: { value: "lab2" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(body).toBeDefined());
    expect(body).toEqual({ name: "lab2" });
    expect(dnsCalls()).toEqual([]);
  });
});

// ── Settings ─────────────────────────────────────────────────────────────────

describe("Settings sections", () => {
  const DNS_SECTIONS = [
    "DNS Defaults",
    "IPAM → DNS Reconciliation",
    "Zone ↔ Server Reconciliation",
    "TLD Registry",
  ];

  function settings() {
    answer("authApi", "me", () => Promise.resolve({ is_superadmin: true }));
    answer("settingsApi", "get", () => Promise.resolve({}));
    answer("settingsApi", "getDefaults", () => Promise.resolve({}));
    open(<SettingsPage />);
  }

  it("lists the DNS sections while DNS is on (control)", async () => {
    settings();
    for (const title of DNS_SECTIONS)
      expect(await screen.findByText(title)).toBeTruthy();
  });

  it("hides them while DNS is off, but keeps the agent bootstrap keys", async () => {
    dnsOff();
    settings();
    expect(await screen.findByText("Agent bootstrap keys")).toBeTruthy();
    for (const title of DNS_SECTIONS)
      expect(screen.queryByText(title)).toBeNull();
  });

  it("hides them until the module set has loaded", async () => {
    mods.ready = false;
    settings();
    expect(await screen.findByText("Agent bootstrap keys")).toBeTruthy();
    for (const title of DNS_SECTIONS)
      expect(screen.queryByText(title)).toBeNull();
    expect(dnsCalls()).toEqual([]);
  });
});

// ── Dashboard ────────────────────────────────────────────────────────────────

describe("Dashboard on a hard reload with the DNS tab persisted", () => {
  beforeEach(() => localStorage.setItem("dashboard-tab", "dns"));

  it("reads no DNS data before the module set has loaded", async () => {
    mods.ready = false;
    open(<DashboardPage />);
    await screen.findByText(/Dashboard/i);
    expect(dnsCalls()).toEqual([]);
    // The persisted choice is kept, not overwritten, while it is unknown.
    expect(localStorage.getItem("dashboard-tab")).toBe("dns");
  });

  it("falls back to Overview and reads no DNS data when DNS is off", async () => {
    dnsOff();
    open(<DashboardPage />);
    await waitFor(() =>
      expect(localStorage.getItem("dashboard-tab")).toBe("overview"),
    );
    expect(dnsCalls()).toEqual([]);
  });

  it("reads the DNS groups while DNS is on (control)", async () => {
    open(<DashboardPage />);
    await waitFor(() => expect(calls).toContain("dnsApi.listGroups"));
  });
});

// ── Admin → IPAM Templates ───────────────────────────────────────────────────

describe("IPAM Templates", () => {
  function templates() {
    answer("ipamTemplatesApi", "list", () => Promise.resolve([]));
    open(<IPAMTemplatesPage />);
  }

  it("has a DNS group column while DNS is on (control)", async () => {
    templates();
    expect(await screen.findByText("DNS group")).toBeTruthy();
  });

  it("drops the column and the group read while DNS is off", async () => {
    dnsOff();
    templates();
    expect(await screen.findByText("DHCP group")).toBeTruthy();
    expect(screen.queryByText("DNS group")).toBeNull();
    expect(dnsCalls()).toEqual([]);
  });
});

// ── Fleet: role assignment ───────────────────────────────────────────────────

describe("Fleet role assignment", () => {
  function roles(assigned: string[] = []) {
    const row = {
      id: "ap-1",
      hostname: "node1",
      assigned_roles: assigned,
      assigned_dns_group_id: null,
      assigned_dhcp_group_id: null,
      capabilities: {
        can_run_dns_bind9: true,
        can_run_dns_powerdns: true,
        can_run_dns_technitium: true,
        can_run_dhcp: true,
        can_run_looking_glass: true,
        can_run_observer: true,
      },
    } as never;
    open(<ApplianceRoleAssignmentSection row={row} onSaved={() => {}} />);
  }

  it("offers the three DNS engines and reads the groups while DNS is on (control)", async () => {
    roles();
    expect(await screen.findByText("DNS · BIND9")).toBeTruthy();
    expect(screen.getByText("DNS · PowerDNS")).toBeTruthy();
    expect(screen.getByText("DNS · Technitium")).toBeTruthy();
    await waitFor(() => expect(calls).toContain("dnsApi.listGroups"));
  });

  it("offers no DNS engine and reads no groups while DNS is off", async () => {
    dnsOff();
    roles();
    expect(await screen.findByText("DHCP")).toBeTruthy();
    expect(screen.queryByText("DNS · BIND9")).toBeNull();
    expect(screen.queryByText("DNS · PowerDNS")).toBeNull();
    expect(screen.queryByText("DNS · Technitium")).toBeNull();
    expect(dnsCalls()).toEqual([]);
  });

  it("offers none before the module set has loaded", async () => {
    mods.ready = false;
    roles();
    expect(await screen.findByText("Observer")).toBeTruthy();
    expect(screen.queryByText("DNS · BIND9")).toBeNull();
    expect(dnsCalls()).toEqual([]);
  });

  it("a DNS role the appliance already holds stays visible, with a note instead of the group picker", async () => {
    dnsOff();
    roles(["dns-bind9"]);
    expect(await screen.findByText("DNS · BIND9")).toBeTruthy();
    expect(screen.queryByText("DNS · PowerDNS")).toBeNull();
    expect(screen.getByText(/DNS is switched off/)).toBeTruthy();
    expect(screen.queryByText("DNS group")).toBeNull();
    expect(dnsCalls()).toEqual([]);
  });
});

// ── IPAM: dialogs ────────────────────────────────────────────────────────────

describe("New Subnet dialog", () => {
  function newSubnet() {
    answer("ipamApi", "listBlocks", () => Promise.resolve([]));
    answer("ipamApi", "listTemplates", () => Promise.resolve([]));
    open(<CreateSubnetModal spaceId="sp-1" onClose={() => {}} />);
  }

  it("has DNS and DDNS tabs while DNS is on (control)", async () => {
    newSubnet();
    expect(await screen.findByRole("button", { name: "DNS" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "DDNS" })).toBeTruthy();
  });

  it("has neither while DNS is off, and DHCP stays", async () => {
    dnsOff();
    newSubnet();
    await screen.findByRole("button", { name: "General" });
    expect(screen.queryByRole("button", { name: "DNS" })).toBeNull();
    expect(screen.queryByRole("button", { name: "DDNS" })).toBeNull();
    expect(screen.getByRole("button", { name: "DHCP" })).toBeTruthy();
    expect(dnsCalls()).toEqual([]);
  });

  it("has neither before the module set has loaded", async () => {
    mods.ready = false;
    newSubnet();
    await screen.findByRole("button", { name: "General" });
    expect(screen.queryByRole("button", { name: "DNS" })).toBeNull();
    expect(dnsCalls()).toEqual([]);
  });
});

describe("Add IP dialog", () => {
  function addIp() {
    answer("ipamApi", "getEffectiveSubnetDns", () =>
      Promise.resolve({
        dns_group_ids: ["g1"],
        dns_zone_id: "z1",
        dns_additional_zone_ids: [],
      }),
    );
    answer("dnsApi", "listZones", () =>
      Promise.resolve([
        { id: "z1", name: "lab.example.", group_id: "g1" },
        { id: "z2", name: "other.example.", group_id: "g1" },
      ]),
    );
    open(<AddAddressModal subnetId="sub-1" onClose={() => {}} />);
  }

  it("has the zone picker and DNS aliases while DNS is on (control)", async () => {
    addIp();
    expect(await screen.findByText("DNS Zone")).toBeTruthy();
    expect(screen.getByText("DNS Aliases")).toBeTruthy();
    expect(calls).toContain("dnsApi.listZones");
  });

  it("has neither, and reads no zones, while DNS is off", async () => {
    dnsOff();
    addIp();
    await screen.findByText("Hostname *");
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByText("DNS Zone")).toBeNull();
    expect(screen.queryByText("DNS Aliases")).toBeNull();
    expect(dnsCalls()).toEqual([]);
  });

  it("reads no zones before the module set has loaded", async () => {
    mods.ready = false;
    addIp();
    await screen.findByText("Hostname *");
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByText("DNS Zone")).toBeNull();
    expect(dnsCalls()).toEqual([]);
  });
});

// ── IPAM: subnet detail ──────────────────────────────────────────────────────

describe("Subnet detail", () => {
  function subnetDetail() {
    // #2571 — Sync > DNS is gated on permissions; this control is about the
    // module being on, so sign in as a superadmin.
    answer("authApi", "myPermissions", () =>
      Promise.resolve({ is_superadmin: true, grants: [] }),
    );
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
      dns_group_ids: ["g1"],
    } as unknown as Subnet;
    open(<SubnetDetail subnet={subnet} onSubnetEdited={() => {}} />);
  }

  const dnsColumn = () =>
    screen
      .queryAllByRole("columnheader")
      .filter((th) => (th.textContent ?? "").trim().startsWith("DNS"));

  it("has the Aliases tab, the DNS column and drift reads while DNS is on (control)", async () => {
    subnetDetail();
    expect(await screen.findByText("Aliases")).toBeTruthy();
    await screen.findByText("hostname");
    expect(dnsColumn().length).toBeGreaterThan(0);
    expect(calls).toContain("ipamApi.dnsSyncSummary");
    expect(calls).toContain("ipamApi.dnsSyncPreview");
  });

  it("has none of them, and reads no DNS data, while DNS is off", async () => {
    dnsOff();
    subnetDetail();
    expect(await screen.findByText("IP Addresses")).toBeTruthy();
    await screen.findByText("hostname");
    expect(screen.queryByText("Aliases")).toBeNull();
    expect(dnsColumn()).toEqual([]);
    expect(dnsCalls()).toEqual([]);
  });

  it("reads no DNS data before the module set has loaded", async () => {
    mods.ready = false;
    subnetDetail();
    await screen.findByText("IP Addresses");
    expect(screen.queryByText("Aliases")).toBeNull();
    expect(dnsCalls()).toEqual([]);
  });

  it("the Sync menu has no DNS entry while DNS is off", async () => {
    dnsOff();
    subnetDetail();
    await screen.findByText("hostname");
    // With neither DNS nor a DHCP scope the menu has nothing to offer, so
    // it is not rendered at all rather than opening onto an empty panel.
    expect(screen.queryByRole("button", { name: /^Sync/ })).toBeNull();
  });

  it("the Sync menu offers DNS while DNS is on (control)", async () => {
    subnetDetail();
    await screen.findByText("hostname");
    fireEvent.click(await screen.findByRole("button", { name: /^Sync/ }));
    expect(await screen.findByRole("menuitem", { name: "DNS" })).toBeTruthy();
  });
});
