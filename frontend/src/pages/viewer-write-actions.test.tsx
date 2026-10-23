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
  return {
    ...actual,
    ...stubs,
  };
});

vi.mock("@/hooks/useFeatureModules", async () => {
  const actual = await vi.importActual<
    typeof import("@/hooks/useFeatureModules")
  >("@/hooks/useFeatureModules");
  return {
    ...actual,
    useFeatureModules: () => ({ ready: true, enabled: () => true }),
  };
});

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
  // #1861 — each tab's create and the reason it is refused: zones, views and
  // ACLs are DNS data on their own resource permission, the rest stay
  // superadmin-only infrastructure.
  const ZONE_WRITE = "Requires write permission on DNS zones";
  const GROUP_WRITE = "Requires write permission on DNS server groups";
  const TAB_CREATES: [string, string, string][] = [
    ["zones", "Add Zone", ZONE_WRITE],
    ["servers", "Add Server", SUPERADMIN],
    ["views", "New View", GROUP_WRITE],
    ["acls", "New ACL", GROUP_WRITE],
    ["blocklists", "New Blocking List", SUPERADMIN],
    ["tsig", "New TSIG Key", SUPERADMIN],
  ];
  // The built-in DNS Editor's grants (app/main.py).
  const DNS_EDITOR: Grant[] = [
    ["admin", "dns_group"],
    ["admin", "dns_zone"],
    ["admin", "dns_record"],
    ["admin", "dns_blocklist"],
    ["read", "manage_dns_pools"],
  ];

  it("offers a Viewer no group, zone or tab write, and says why", async () => {
    signInAs(VIEWER);
    await openDns("zones");
    expectDenied(GROUP_WRITES, SUPERADMIN);
    expectDenied(["Add Zone", /From Template/], ZONE_WRITE);
    // The tree's "New server group" is an icon button: while denied it is
    // named by its tooltip, the reason (as #1175's icon buttons are).
    expect(
      screen.queryByRole("button", { name: "New server group" }),
    ).toBeNull();
    for (const tab of TAB_CREATES.slice(1)) {
      cleanup();
      await openDns(tab[0]);
      expectDenied([tab[1]], tab[2]);
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

  it("the n shortcut opens no Add Record for a Viewer (#2529)", async () => {
    signInAs(VIEWER);
    await openDns("zones");
    await openZone();
    await act(async () => {
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "n" }));
    });
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("the n shortcut still opens Add Record for a record writer (#2529)", async () => {
    signInAs([...VIEWER, ["write", "dns_record"]]);
    await openDns("zones");
    await openZone();
    await act(async () => {
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "n" }));
    });
    expect(await screen.findByRole("dialog")).toBeTruthy();
  });

  it("offers a record writer the records, and still not the zone", async () => {
    signInAs([...VIEWER, ["write", "dns_record"]]);
    await openDns("zones");
    expectDenied(GROUP_WRITES, SUPERADMIN);
    expectDenied(["Add Zone"], ZONE_WRITE);
    await openZone();
    expectOffered([/Add Record/]);
    expect(button(/^Zone$/).disabled).toBe(true);
  });

  it("offers the built-in DNS Editor zones, views and ACLs, not the infrastructure (#1861)", async () => {
    signInAs(DNS_EDITOR);
    await openDns("zones");
    expectDenied(GROUP_WRITES, SUPERADMIN);
    expectOffered(["Add Zone", /From Template/]);
    await openZone();
    expectOffered([/Add Record/, /^Zone$/]);
    for (const [tab, create, reason] of TAB_CREATES.slice(1)) {
      cleanup();
      await openDns(tab);
      if (reason === SUPERADMIN) expectDenied([create], SUPERADMIN);
      else expectOffered([create]);
    }
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

  // #1861 — each Kea tab's create and the permission it asks for.
  const KEA_TABS: [string, string, string][] = [
    [
      "Client Classes",
      "New Client Class",
      "Requires write permission on DHCP client classes",
    ],
    [
      "Option Templates",
      "New Template",
      "Requires write permission on DHCP option templates",
    ],
    ["MAC Blocks", "Block MAC", "Requires write permission on DHCP MAC blocks"],
    [
      "Phone Profiles",
      "New Phone Profile",
      "Requires write permission on DHCP scopes",
    ],
    [
      "Device Policies",
      "New Policy",
      "Requires write permission on DHCP client classes",
    ],
  ];
  // The built-in DHCP Editor's grants (app/main.py).
  const DHCP_EDITOR: Grant[] = [
    ["admin", "dhcp_server"],
    ["admin", "dhcp_scope"],
    ["admin", "dhcp_pool"],
    ["admin", "dhcp_static"],
    ["admin", "dhcp_client_class"],
    ["admin", "dhcp_option_template"],
    ["admin", "dhcp_mac_block"],
  ];

  async function eachKeaTab(check: (create: string, reason: string) => void) {
    for (const [tab, create, reason] of KEA_TABS) {
      button(tab).click();
      await screen.findByRole("button", { name: create });
      check(create, reason);
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
    await eachKeaTab((create, reason) => expectDenied([create], reason));
  });

  it("offers the built-in DHCP Editor every Kea-tab write, not the servers (#1861)", async () => {
    signInAs(DHCP_EDITOR);
    await openDhcp();
    expectDenied(
      ["Edit Group", "Delete Group", "Add Server", /^Pause\b/],
      SUPERADMIN,
    );
    await eachKeaTab((create) => expectOffered([create]));
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

// ── #1341: Administration, Tools and the IPAM side pages ─────────────────────

/** route, the page module and export, and the write the check reads. */
const ADMIN_TOOLS_PAGES: [string, string, string, string][] = [
  ["/admin/users", "admin/UsersPage", "UsersPage", "New User"],
  ["/admin/groups", "admin/GroupsPage", "GroupsPage", "New Group"],
  ["/admin/webhooks", "admin/WebhooksPage", "WebhooksPage", "New subscription"],
  ["/admin/alerts", "admin/AlertsPage", "AlertsPage", "New rule"],
  [
    "/admin/ipam/templates",
    "admin/IPAMTemplatesPage",
    "IPAMTemplatesPage",
    "New template",
  ],
  ["/admin/domains", "admin/DomainsPage", "DomainsPage", "New domain"],
  [
    "/tools/wake-schedules",
    "tools/WakeSchedulesPage",
    "WakeSchedulesPage",
    "New schedule",
  ],
  ["/tools/nmap", "nmap/NmapToolsPage", "NmapToolsPage", "Start scan"],
  [
    "/tools/pcap",
    "pcap/PacketCapturePage",
    "PacketCapturePage",
    "Start capture",
  ],
  [
    "/security/new-devices",
    "security/NewDevicesPage",
    "NewDevicesPage",
    "Run baseline import",
  ],
  [
    "/security/firewall-feeds",
    "firewall_feeds/FirewallFeedsPage",
    "FirewallFeedsPage",
    "New feed",
  ],
  ["/ipam/nat", "ipam/NATPage", "NATPage", "New mapping"],
  [
    "/ipam/plans",
    "ipam/SubnetPlannerListPage",
    "SubnetPlannerListPage",
    "New plan",
  ],
];

const ROLE = {
  id: "role-1",
  name: "viewer-role",
  description: "",
  is_builtin: false,
  permissions: [{ action: "read", resource_type: "subnet", resource_id: null }],
};

const MODULES = [
  {
    id: "core.dhcp",
    label: "DHCP",
    group: "DHCP",
    enabled: true,
    requires: [],
  },
  {
    id: "reports.top_n",
    label: "Top-N reports",
    group: "Compliance",
    enabled: true,
    requires: [],
  },
].map((m) => ({
  ...m,
  description: `${m.label} description`,
  default_enabled: true,
}));

describe("#1341 Administration, Tools and the IPAM side pages", () => {
  async function openAndRead(
    route: string,
    module: string,
    name: string,
    write: string,
  ) {
    await openPage(route, module, name);
    await screen.findAllByRole("button", { name: write });
    await permissionsLoaded();
  }

  it("offers a Viewer none of their writes, and says why", async () => {
    signInAs(VIEWER);
    for (const [route, module, name, write] of ADMIN_TOOLS_PAGES) {
      cleanup();
      await openAndRead(route, module, name, write);
      expect(expectAllDenied(write, /^Requires /), route).toBeGreaterThan(0);
    }
  });

  it("offers a Viewer no role write: a role opens to be read, not edited", async () => {
    signInAs(VIEWER);
    answers.rolesApi = { list: async () => [ROLE] };
    await openAndRead(
      "/admin/roles",
      "admin/RolesPage",
      "RolesPage",
      "New Role",
    );
    expectAllDenied("New Role", /^Requires admin permission on roles$/);
    const row = (await screen.findByText("viewer-role")).closest("tr")!;
    const [view, clone, del] = Array.from(row.querySelectorAll("button"));
    expect(view.title).toBe("View");
    expect([clone.disabled, clone.title]).toEqual([
      true,
      "Requires admin permission on roles",
    ]);
    expect([del.disabled, del.title]).toEqual([
      true,
      "Requires admin permission on roles",
    ]);
  });

  it("offers a Viewer none of the Features page's switches", async () => {
    signInAs(VIEWER);
    answers.featureModulesApi = { list: async () => MODULES };
    await openPage("/admin/features", "admin/FeaturesPage", "FeaturesPage");
    await screen.findByText("DHCP description");
    await permissionsLoaded();
    const switches = screen.getAllByRole("switch") as HTMLButtonElement[];
    expect(switches.length).toBeGreaterThan(0);
    expect(switches.filter((s) => !s.disabled)).toEqual([]);
    expect(switches[0].title).toBe(SUPERADMIN);
  });

  it("offers a superadmin every one of them", async () => {
    signInAs("superadmin");
    for (const [route, module, name, write] of ADMIN_TOOLS_PAGES) {
      cleanup();
      await openAndRead(route, module, name, write);
      for (const b of screen.getAllByRole("button", { name: write })) {
        expect((b as HTMLButtonElement).disabled, `${route} ${write}`).toBe(
          false,
        );
      }
    }
    cleanup();
    answers.rolesApi = { list: async () => [ROLE] };
    await openAndRead(
      "/admin/roles",
      "admin/RolesPage",
      "RolesPage",
      "New Role",
    );
    expectOffered(["New Role"]);
    const row = (await screen.findByText("viewer-role")).closest("tr")!;
    expect(
      Array.from(row.querySelectorAll("button")).map((b) => [
        b.title,
        b.disabled,
      ]),
    ).toEqual([
      ["Edit", false],
      ["Clone", false],
      ["Delete", false],
    ]);
    cleanup();
    answers.featureModulesApi = { list: async () => MODULES };
    await openPage("/admin/features", "admin/FeaturesPage", "FeaturesPage");
    await screen.findByText("DHCP description");
    await permissionsLoaded();
    const switches = screen.getAllByRole("switch") as HTMLButtonElement[];
    expect(switches.filter((s) => s.disabled)).toEqual([]);
  });
});

// ── #1342: the Appliance tabs ────────────────────────────────────────────────

const APPLIANCE_ADMIN = "Requires admin permission on the appliance";

const SYSTEM_INFO = {
  hostname: "appliance-1",
  host_ips: ["192.0.2.10"],
  uptime_seconds: 3600,
  maintenance_mode: false,
  reboot_pending_from_host: false,
  reboot_scheduled: false,
  appliance_version: "2026.10.05-1",
  appliance_mode: true,
};

const POLICY = {
  id: "pol-1",
  name: "viewer-policy",
  description: null,
  scope_kind: "role",
  scope_role: "dns",
  scope_appliance_id: null,
  enabled: true,
  is_builtin: false,
  priority: 100,
  rules: [],
};

function applianceAnswers() {
  answers.applianceSystemApi = { info: async () => SYSTEM_INFO };
  answers.applianceContainersApi = {
    list: async () => [
      {
        name: "api",
        image: "spatiumddi-api",
        state: "running",
        status: "Up 1 hour",
        health: "healthy",
        short_id: "abc123",
        started_at: STAMP,
        is_spatium: true,
      },
    ],
  };
  answers.firewallApi = {
    getEnforcement: async () => ({
      enabled: false,
      logging_enabled: false,
      reported_count: 1,
      hardened_count: 1,
      lanwide_count: 0,
      all_hardened: true,
      safe_to_enable: true,
      nodes: [],
    }),
    listPolicies: async () => [POLICY],
    listAliases: async () => [],
    getWebUIAccess: async () => ({
      allowed_cidrs: [],
      open: true,
      caller_ip: "192.0.2.50",
      caller_covered: true,
    }),
  };
  answers.applianceSetupApi = {
    state: async () => ({
      complete: false,
      completed_at: null,
      completed_by: null,
    }),
  };
  answers.applianceTlsApi = { list: async () => [] };
}

/** tab, the component's module and export, and the controls it must gate.
 *  Cluster › Overview's Reboot host renders only under a live cluster-health
 *  snapshot; the deep-tier ui check reads it on a running appliance. */
const APPLIANCE_TABS: [string, string, string, (string | RegExp)[]][] = [
  [
    "Maintenance",
    "./appliance/MaintenanceTab.tsx",
    "MaintenanceTab",
    ["Enable", "Reboot now"],
  ],
  [
    "Cluster › Pods",
    "./appliance/ContainersTab.tsx",
    "ContainersTab",
    ["Restart", "Stop"],
  ],
  [
    "Firewall",
    "./appliance/FirewallTab.tsx",
    "FirewallTab",
    ["Enable…", "New policy", "Edit rules", "Edit…"],
  ],
  [
    "Setup",
    "./appliance/SetupWizardPage.tsx",
    "SetupWizardPage",
    ["Finish setup"],
  ],
];

const applianceModules = import.meta.glob("./appliance/*.tsx");

async function openTab(module: string, name: string, first: string | RegExp) {
  const mod = (await applianceModules[module]()) as Record<
    string,
    () => ReactNode
  >;
  const Tab = mod[name];
  show(<Tab />, "/appliance");
  await screen.findAllByRole("button", { name: first });
  await permissionsLoaded();
}

describe("#1342 the Appliance tabs", () => {
  it("offers a Viewer none of the appliance's actions, and says why", async () => {
    signInAs(VIEWER);
    for (const [, module, name, controls] of APPLIANCE_TABS) {
      cleanup();
      applianceAnswers();
      await openTab(module, name, controls[0]);
      for (const c of controls) {
        expect(
          expectAllDenied(c, new RegExp(`^${APPLIANCE_ADMIN}$`)),
          `${name} ${String(c)}`,
        ).toBeGreaterThan(0);
      }
      // The posture presets: every Apply preset is denied too.
      if (name === "FirewallTab")
        expectAllDenied("Apply preset", /^Requires admin/);
    }
  });

  it("offers an appliance admin every one of them", async () => {
    signInAs([...VIEWER, ["admin", "appliance"]]);
    for (const [, module, name, controls] of APPLIANCE_TABS) {
      cleanup();
      applianceAnswers();
      await openTab(module, name, controls[0]);
      for (const c of controls) {
        for (const b of screen.getAllByRole("button", { name: c })) {
          expect(
            (b as HTMLButtonElement).disabled,
            `${name} ${String(c)}`,
          ).toBe(false);
        }
      }
    }
  });
});

// ── Rows and toolbars the first pass left open ────────────────────────────────

const FEED = {
  id: "feed-1",
  name: "viewer-feed",
  description: "",
  enabled: true,
  kind: "ip",
  poll_path: "/feeds/x/blocklist.txt",
  last_polled_at: null,
  last_polled_ip: null,
  poll_count: 0,
  created_at: "2026-10-01T00:00:00Z",
  modified_at: "2026-10-01T00:00:00Z",
};

const CLOUD_ENDPOINT = {
  id: "cloud-1",
  name: "viewer-cloud",
  description: "",
  enabled: true,
  provider: "aws",
  credentials_present: true,
  provider_config: {},
  regions: [],
  ipam_space_id: "space-1",
  public_space_id: null,
  dns_group_id: null,
  mirror_load_balancers: false,
  mirror_stopped_instances: false,
  sync_interval_seconds: 300,
  last_synced_at: null,
  last_sync_error: null,
  provider_account_id: null,
  network_count: null,
  instance_count: null,
  last_discovery: null,
  created_at: "2026-10-01T00:00:00Z",
  modified_at: "2026-10-01T00:00:00Z",
};

describe("rows and toolbars the first pass left open", () => {
  async function rowButtons(text: string) {
    const row = (await screen.findByText(text)).closest("tr")!;
    await permissionsLoaded();
    return Array.from(row.querySelectorAll("button"));
  }

  it("offers a Viewer none of a firewall feed's row actions, Reveal and Rotate included", async () => {
    signInAs(VIEWER);
    answers.firewallFeedsApi = { list: async () => [FEED] };
    await openPage(
      "/security/firewall-feeds",
      "firewall_feeds/FirewallFeedsPage",
      "FirewallFeedsPage",
    );
    const buttons = await rowButtons("viewer-feed");
    expect(buttons.length).toBeGreaterThanOrEqual(4);
    for (const b of buttons) {
      expect([b.title, b.disabled]).toEqual([SUPERADMIN, true]);
    }
  });

  it("offers a superadmin a firewall feed's row actions", async () => {
    signInAs("superadmin");
    answers.firewallFeedsApi = { list: async () => [FEED] };
    await openPage(
      "/security/firewall-feeds",
      "firewall_feeds/FirewallFeedsPage",
      "FirewallFeedsPage",
    );
    for (const b of await rowButtons("viewer-feed")) {
      expect(b.disabled, b.title).toBe(false);
    }
  });

  it("offers a Viewer none of a cloud endpoint's row actions, Sync now included", async () => {
    signInAs(VIEWER);
    answers.cloudApi = { listEndpoints: async () => [CLOUD_ENDPOINT] };
    await openPage("/cloud", "cloud/CloudPage", "CloudPage");
    const buttons = await rowButtons("viewer-cloud");
    expect(buttons.length).toBeGreaterThanOrEqual(4);
    for (const b of buttons) {
      expect([b.title, b.disabled]).toEqual([SUPERADMIN, true]);
    }
  });

  it("offers a Viewer no alert evaluation", async () => {
    signInAs(VIEWER);
    answers.alertsApi = {
      listRules: async () => [],
      listEvents: async () => [],
    };
    await openPage("/admin/alerts", "admin/AlertsPage", "AlertsPage");
    await screen.findByRole("button", { name: /Evaluate now/ });
    await permissionsLoaded();
    expectDenied([/Evaluate now/], SUPERADMIN);
  });
});
