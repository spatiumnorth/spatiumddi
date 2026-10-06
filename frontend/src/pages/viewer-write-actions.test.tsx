/**
 * @vitest-environment jsdom
 *
 * A read-only user is offered no write it would be refused (#1338, #1339,
 * #1340, #1341, #1342).
 *
 * #1175 gated IPAM with `permissionGate()` (#1155); every other part of the
 * console still offered the built-in Viewer (read on everything) its write
 * controls, enabled, and the server refused each only after the form was
 * filled in. These render the real pages with the real `usePermissions`
 * hook against the permission set `GET /auth/me/permissions` returns, and
 * read each control the way the operator meets it: disabled, with the
 * reason as its tooltip, or not there at all. A superadmin (and, where the
 * route takes a grant rather than a superadmin, an operator holding that
 * grant) is offered every one of them, so a gate that never opens fails
 * too. Every API call a test does not answer stays pending.
 */

import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

type Answer = (...args: unknown[]) => unknown;
/** Per API object, the calls a test answers. Anything else stays pending. */
const answers: Record<string, Record<string, Answer>> = {};

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
                : (...args: unknown[]) =>
                    (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const SUPERADMIN = "Requires superadmin";

type Grant = [action: string, resourceType: string];
/** The built-in Viewer role: read on everything. */
const VIEWER: Grant[] = [["read", "*"]];

const myPermissions = vi.fn();

function signInAs(grants: Grant[] | "superadmin") {
  myPermissions.mockResolvedValue(
    grants === "superadmin"
      ? { is_superadmin: true, grants: [] }
      : {
          is_superadmin: false,
          grants: grants.map(([action, resource_type]) => ({
            action,
            resource_type,
            resource_id: null,
          })),
        },
  );
  answers.authApi = { myPermissions: () => myPermissions() };
}

function show(ui: ReactNode, url = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Let the permission answer land: while it loads every gate is closed
 *  (usePermissions fails closed), which would pass a Viewer case for the
 *  wrong reason. A page that never asks for it (the defect) is read as it
 *  renders. */
async function permissionsLoaded() {
  await waitFor(() => expect(myPermissions).toHaveBeenCalled(), {
    timeout: 500,
  }).catch(() => undefined);
  await act(async () => {});
}

function button(name: string | RegExp): HTMLButtonElement {
  return screen.getByRole("button", { name }) as HTMLButtonElement;
}

/** Each named control is disabled and says why. */
function expectDenied(names: (string | RegExp)[], reason: string) {
  for (const name of names) {
    const b = button(name);
    expect(b.disabled, `${String(name)} is offered`).toBe(true);
    expect(b.title, `${String(name)} does not say why`).toBe(reason);
  }
}

function expectOffered(names: (string | RegExp)[]) {
  for (const name of names) {
    expect(button(name).disabled, `${String(name)} is not offered`).toBe(false);
  }
}

// The walks render up to 16 pages each; on a build whose pages never ask for
// the permission set, every page waits out permissionsLoaded()'s 500 ms.
vi.setConfig({ testTimeout: 30_000 });

afterEach(() => {
  cleanup();
  for (const k of Object.keys(answers)) delete answers[k];
  myPermissions.mockReset();
  localStorage.clear();
  sessionStorage.clear();
});

// ── #1338: the DNS page ───────────────────────────────────────────────────────

const STAMP = "2026-10-06T00:00:00Z";

const DNS_GROUP = {
  id: "grp-1",
  name: "viewer-walk",
  description: "",
  group_type: "internal",
  default_view: null,
  is_recursive: false,
  catalog_zones_enabled: false,
  catalog_zone_name: "",
  server_drivers: ["bind9"],
  created_at: STAMP,
  modified_at: STAMP,
};

const ZONE = {
  id: "zone-1",
  group_id: "grp-1",
  view_id: null,
  name: "viewer.test.",
  zone_type: "primary",
  kind: "forward",
  ttl: 3600,
  refresh: 86400,
  retry: 7200,
  expire: 3600000,
  minimum: 3600,
  primary_ns: "ns1.viewer.test.",
  admin_email: "admin.viewer.test.",
  is_auto_generated: false,
  linked_subnet_id: null,
  dnssec_enabled: false,
  dnssec_ds_records: null,
  dnssec_synced_at: null,
  color: null,
  last_serial: 1,
  last_pushed_at: null,
  allow_query: null,
  allow_transfer: null,
  also_notify: null,
  notify_enabled: null,
  forwarders: [],
  forward_only: false,
  masters: [],
  tailscale_tenant_id: null,
  customer_id: null,
  name_scope: "private",
  created_at: STAMP,
  modified_at: STAMP,
};

describe("#1338 the DNS page", () => {
  async function openDns(tab: string) {
    answers.dnsApi = {
      listGroups: async () => [DNS_GROUP],
      listZones: async () => [ZONE],
      listViews: async () => [],
      listServers: async () => [],
      listAcls: async () => [],
      listTSIGKeys: async () => [],
    };
    answers.dnsBlocklistApi = { list: async () => [] };
    const { DNSPage } = await import("@/pages/dns/DNSPage");
    show(<DNSPage />, `/dns?group=grp-1&tab=${tab}`);
    await screen.findByRole("button", { name: /^Edit Group$/ });
    await permissionsLoaded();
  }

  /** The zone's own view: its name in the zones table opens it. */
  async function openZone() {
    const name = (await screen.findAllByText(/viewer\.test/)).find((el) =>
      el.closest("tr"),
    );
    name!.click();
    await screen.findByRole("button", { name: /Add Record/ });
  }

  const GROUP_WRITES = ["Sync with Servers", "Edit Group", "Delete Group"];
  const TAB_CREATES: [string, string][] = [
    ["zones", "Add Zone"],
    ["servers", "Add Server"],
    ["views", "New View"],
    ["acls", "New ACL"],
    ["blocklists", "New Blocking List"],
    ["tsig", "New TSIG Key"],
  ];

  it("offers a Viewer no group, zone or tab write, and says why", async () => {
    signInAs(VIEWER);
    await openDns("zones");
    expectDenied(GROUP_WRITES, SUPERADMIN);
    expectDenied(["Add Zone", /From Template/], SUPERADMIN);
    // The tree's "New server group" is an icon button: while denied it is
    // named by its tooltip, the reason (as #1175's icon buttons are).
    expect(
      screen.queryByRole("button", { name: "New server group" }),
    ).toBeNull();
    for (const tab of TAB_CREATES.slice(1)) {
      cleanup();
      await openDns(tab[0]);
      expectDenied([tab[1]], SUPERADMIN);
    }
  });

  it("offers a Viewer neither Add Record nor any of the Zone menu", async () => {
    signInAs(VIEWER);
    await openDns("zones");
    await openZone();
    expectDenied([/Add Record/], "Requires write permission on DNS records");
    // Every item of Zone ▾ is a write, so the menu itself is not offered.
    expect(button(/^Zone$/).disabled).toBe(true);
  });

  it("offers a record writer the records, and still not the zone", async () => {
    signInAs([...VIEWER, ["write", "dns_record"]]);
    await openDns("zones");
    expectDenied([...GROUP_WRITES, "Add Zone"], SUPERADMIN);
    await openZone();
    expectOffered([/Add Record/]);
    expect(button(/^Zone$/).disabled).toBe(true);
  });

  it("offers a superadmin every one of them", async () => {
    signInAs("superadmin");
    await openDns("zones");
    expectOffered([...GROUP_WRITES, "Add Zone", /From Template/]);
    expect(
      screen.getAllByRole("button", { name: "New server group" }).length,
    ).toBeGreaterThan(0);
    await openZone();
    expectOffered([/Add Record/, /^Zone$/]);
    for (const tab of TAB_CREATES.slice(1)) {
      cleanup();
      await openDns(tab[0]);
      expectOffered([tab[1]]);
    }
  });
});

// ── #1339: the DHCP page ──────────────────────────────────────────────────────

const DHCP_GROUP = {
  id: "dgrp-1",
  name: "viewer-walk",
  description: "",
  mode: "standalone",
  heartbeat_delay_ms: 10000,
  max_response_delay_ms: 60000,
  max_ack_delay_ms: 10000,
  max_unacked_clients: 5,
  auto_failover: true,
  lease_cache_threshold: 0,
  lease_cache_max_age: null,
  kea_thread_pool_size: 0,
  kea_packet_logging: false,
  kea_member_count: 1,
  servers: [],
  created_at: STAMP,
  modified_at: STAMP,
};

const DHCP_SERVER = {
  id: "srv-1",
  server_group_id: "dgrp-1",
  name: "kea-viewer",
  description: "",
  driver: "kea",
  host: "192.0.2.98",
  port: 8000,
  roles: [],
  status: "active",
  last_sync_at: null,
  last_health_check_at: null,
  agent_registered: true,
  agent_approved: true,
  agent_last_seen: null,
  last_seen_ip: null,
  config_apply_status: null,
  config_apply_error: null,
  config_failed_etag: null,
  config_apply_at: null,
  spool_status: null,
  daemon_status: null,
  daemon_reason: null,
  daemon_status_since: null,
  daemon_not_serving: null,
  agent_version: null,
  config_etag: null,
  config_pushed_at: null,
  has_credentials: false,
  is_agentless: false,
  is_read_only: false,
  maintenance_mode: false,
  maintenance_started_at: null,
  maintenance_reason: null,
  created_at: STAMP,
  modified_at: STAMP,
};

describe("#1339 the DHCP page", () => {
  async function openDhcp() {
    answers.dhcpApi = {
      listGroups: async () => [DHCP_GROUP],
      listServers: async () => [DHCP_SERVER],
      listScopesByGroup: async () => [],
      listClientClasses: async () => [],
      listOptionTemplates: async () => [],
      listMacBlocks: async () => [],
      listPhoneProfiles: async () => [],
      listVoipVendors: async () => [],
      listDevicePolicies: async () => [],
    };
    const { DHCPPage } = await import("@/pages/dhcp/DHCPPage");
    show(<DHCPPage />, "/dhcp?group=dgrp-1");
    await screen.findByText("kea-viewer");
    await permissionsLoaded();
  }

  const KEA_TABS: [string, string][] = [
    ["Client Classes", "New Client Class"],
    ["Option Templates", "New Template"],
    ["MAC Blocks", "Block MAC"],
    ["Phone Profiles", "New Phone Profile"],
    ["Device Policies", "New Policy"],
  ];

  async function eachKeaTab(check: (create: string) => void) {
    for (const [tab, create] of KEA_TABS) {
      button(tab).click();
      await screen.findByRole("button", { name: create });
      check(create);
    }
  }

  it("offers a Viewer no group, server or Kea-tab write, and says why", async () => {
    signInAs(VIEWER);
    await openDhcp();
    expectDenied(
      ["Edit Group", "Delete Group", "Add Server", /^Pause\b/],
      SUPERADMIN,
    );
    // The icon buttons are named by their tooltip, the reason, while denied.
    for (const name of ["New group", "Edit server", "Delete server"]) {
      expect(screen.queryByRole("button", { name })).toBeNull();
    }
    await eachKeaTab((create) => expectDenied([create], SUPERADMIN));
  });

  it("offers a superadmin every one of them", async () => {
    signInAs("superadmin");
    await openDhcp();
    expectOffered(["Edit Group", "Delete Group", "Add Server", /^Pause\b/]);
    expectOffered(["Edit server", "Delete server"]);
    expect(
      screen.getAllByRole("button", { name: "New group" }).length,
    ).toBeGreaterThan(0);
    await eachKeaTab((create) => expectOffered([create]));
  });
});

// ── #1340: the Network and integration pages ─────────────────────────────────

/** Every button by this name (a page can show its create both in its header
 *  and in its empty state) is disabled and says why. */
function expectAllDenied(name: string | RegExp, reason: RegExp) {
  const all = screen.queryAllByRole("button", { name }) as HTMLButtonElement[];
  for (const b of all) {
    expect(b.disabled, `${String(name)} is offered`).toBe(true);
    expect(b.title, `${String(name)} does not say why`).toMatch(reason);
  }
  return all.length;
}

const CUSTOMER = {
  id: "cust-1",
  name: "viewer-customer",
  account_number: null,
  contact_email: null,
  contact_phone: null,
  contact_address: null,
  status: "active",
  notes: "",
  tags: {},
  custom_fields: {},
  created_at: STAMP,
  modified_at: STAMP,
};

/** route, the page module and export, and the create the check reads. */
const NETWORK_PAGES: [string, string, string, string][] = [
  [
    "/network/customers",
    "network/CustomersPage",
    "CustomersPage",
    "New customer",
  ],
  [
    "/network/providers",
    "network/ProvidersPage",
    "ProvidersPage",
    "New provider",
  ],
  ["/network/sites", "network/SitesPage", "SitesPage", "New site"],
  ["/network/services", "network/ServicesPage", "ServicesPage", "New service"],
  ["/network/circuits", "network/CircuitsPage", "CircuitsPage", "New circuit"],
  ["/network/overlays", "network/OverlaysPage", "OverlaysPage", "New overlay"],
  ["/network/vrfs", "vrfs/VRFsPage", "VRFsPage", "New VRF"],
  [
    "/network/multicast",
    "network/MulticastGroupsPage",
    "MulticastGroupsPage",
    "New group",
  ],
  [
    "/network/certificates",
    "network/CertificatesPage",
    "CertificatesPage",
    "New target",
  ],
  ["/network/devices", "network/NetworkPage", "NetworkPage", "Add Device"],
  ["/network/asns", "network/AsnsPage", "AsnsPage", "New ASN"],
  ["/cloud", "cloud/CloudPage", "CloudPage", "Add account"],
  ["/docker", "docker/DockerPage", "DockerPage", "Add Host"],
  ["/proxmox", "proxmox/ProxmoxPage", "ProxmoxPage", "Add Endpoint"],
  ["/unifi", "unifi/UnifiPage", "UnifiPage", "Add Controller"],
];

const pageModules = import.meta.glob("./**/*Page.tsx");

async function openPage(route: string, module: string, name: string) {
  const mod = (await pageModules[`./${module}.tsx`]()) as Record<
    string,
    () => ReactNode
  >;
  const Page = mod[name];
  show(<Page />, route);
}

describe("#1340 the Network and integration pages", () => {
  it("offers a Viewer no create on any of them, and says why", async () => {
    signInAs(VIEWER);
    for (const [route, module, name, create] of NETWORK_PAGES) {
      cleanup();
      await openPage(route, module, name);
      await screen.findAllByRole("button", { name: create });
      await permissionsLoaded();
      expect(expectAllDenied(create, /^Requires /), `${route}`).toBeGreaterThan(
        0,
      );
    }
    // VLANs' "New Router" is an icon button: named by its reason while denied.
    cleanup();
    await openPage("/network/vlans", "vlans/VLANsPage", "VLANsPage");
    await screen.findByTitle(/^Refresh routers/);
    await permissionsLoaded();
    expect(screen.queryByRole("button", { name: "New Router" })).toBeNull();
  });

  it("offers a Viewer neither a customer's Edit nor its Delete", async () => {
    signInAs(VIEWER);
    answers.customersApi = {
      list: async () => ({
        items: [CUSTOMER],
        total: 1,
        limit: 500,
        offset: 0,
      }),
    };
    await openPage(
      "/network/customers",
      "network/CustomersPage",
      "CustomersPage",
    );
    const row = (await screen.findByText("viewer-customer")).closest("tr")!;
    await permissionsLoaded();
    // Icon buttons, named by their tooltip: the reason while denied.
    const rowButtons = Array.from(row.querySelectorAll("button"));
    expect(rowButtons.map((b) => [b.title, b.disabled])).toEqual([
      ["Requires write permission on customers", true],
      ["Requires delete permission on customers", true],
    ]);
  });

  it("offers an operator exactly the registry it may write", async () => {
    signInAs([...VIEWER, ["write", "customer"]]);
    await openPage(
      "/network/customers",
      "network/CustomersPage",
      "CustomersPage",
    );
    await screen.findAllByRole("button", { name: "New customer" });
    await permissionsLoaded();
    expectOffered(["New customer"]);
    cleanup();
    await openPage(
      "/network/providers",
      "network/ProvidersPage",
      "ProvidersPage",
    );
    await screen.findAllByRole("button", { name: "New provider" });
    await permissionsLoaded();
    expectAllDenied("New provider", /^Requires write permission on providers$/);
  });

  it("offers a superadmin every one of them", async () => {
    signInAs("superadmin");
    for (const [route, module, name, create] of NETWORK_PAGES) {
      cleanup();
      await openPage(route, module, name);
      await screen.findAllByRole("button", { name: create });
      await permissionsLoaded();
      for (const b of screen.getAllByRole("button", { name: create })) {
        expect((b as HTMLButtonElement).disabled, `${route} ${create}`).toBe(
          false,
        );
      }
    }
    cleanup();
    await openPage("/network/vlans", "vlans/VLANsPage", "VLANsPage");
    await screen.findByTitle(/^Refresh routers/);
    await permissionsLoaded();
    expectOffered(["New Router"]);
  });
});
