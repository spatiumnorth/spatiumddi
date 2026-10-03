/**
 * @vitest-environment jsdom
 *
 * A refused action says it was refused (#1344).
 *
 * The console reported several refused requests (403) as done, or not at
 * all: the zones tab's bulk Delete closed its dialog, cleared the selection
 * and left the zone; Delete Zone, the DHCP server's Pause and Delete
 * server, and Delete role left their dialog open with no word; and the
 * propagation check painted every resolver "OK" when its own request
 * failed. A read-only Viewer meets these first, but nothing about them is
 * specific to the Viewer: the mutations never read their own failure.
 *
 * These drive the real pages through the same steps an operator takes and
 * answer the one request with the 403 the API sends, carrying its own
 * `detail`. The contract: the refusal is said in words, where the action
 * was taken, and nothing is reported as done. Every other API call the
 * pages make stays pending, so nothing here depends on data it was not
 * given.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

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

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: true,
      isLoading: false,
    }),
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { DNSPage } = await import("@/pages/dns/DNSPage");
const { PropagationCheckModal } =
  await import("@/pages/dns/PropagationCheckModal");
const { DHCPPage } = await import("@/pages/dhcp/DHCPPage");
const { RolesPage } = await import("@/pages/admin/RolesPage");

/** The rejection axios produces for a 403 carrying the route's `detail`. */
function refusal(detail: string) {
  return Object.assign(new Error("Request failed with status code 403"), {
    isAxiosError: true,
    status: 403,
    response: { status: 403, data: { detail } },
  });
}

const DNS_DENIED =
  "Permission denied: need 'delete' on one of ['dns_group', 'dns_zone', 'dns_record']";
const STAMP = "2026-09-30T00:00:00Z";

const DNS_GROUP = {
  id: "grp-1",
  name: "refusals",
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
  name: "refused.test.",
  zone_type: "primary",
  kind: "forward",
  ttl: 3600,
  refresh: 86400,
  retry: 7200,
  expire: 3600000,
  minimum: 3600,
  primary_ns: "ns1.refused.test.",
  admin_email: "admin.refused.test.",
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

const DHCP_GROUP = {
  id: "dgrp-1",
  name: "refusals",
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
  name: "kea-refused",
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

function show(ui: ReactNode, url = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

/** The dialog the operator is looking at: the last one opened. */
function topDialog(): HTMLElement {
  const dialogs = screen.getAllByRole("dialog");
  return dialogs[dialogs.length - 1];
}

afterEach(() => {
  cleanup();
  for (const k of Object.keys(answers)) delete answers[k];
  localStorage.clear();
  sessionStorage.clear();
});

describe("DNS: a refused zone delete", () => {
  const SECOND = { ...ZONE, id: "zone-2", name: "deletable.test." };

  function dnsAnswers(deleteZone: Answer, zones: object[] = [ZONE]) {
    answers.dnsApi = {
      listGroups: async () => [DNS_GROUP],
      listZones: async () => zones,
      listViews: async () => [],
      deleteZone,
    };
  }

  /** Zones tab → select every zone → Delete N → Continue → acknowledge →
   *  Delete: the steps an operator takes. */
  async function bulkDelete(count: number) {
    show(<DNSPage />, "/dns?group=grp-1&tab=zones");
    fireEvent.click(await screen.findByLabelText("Select all filtered zones"));
    fireEvent.click(
      screen.getByRole("button", { name: new RegExp(`^Delete ${count}$`) }),
    );
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: /^Continue$/ }),
    );
    fireEvent.click(within(topDialog()).getByRole("checkbox"));
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: /^Delete$/ }),
    );
  }

  it("bulk Delete keeps the dialog and the selection, and says why", async () => {
    const deleteZone = vi.fn(() => Promise.reject(refusal(DNS_DENIED)));
    dnsAnswers(deleteZone);
    await bulkDelete(1);

    await waitFor(() => expect(deleteZone).toHaveBeenCalledTimes(1));
    // Said in words, in the dialog the operator confirmed in…
    const said = await screen.findByText(/Permission denied/);
    expect(said.closest('[role="dialog"]')).toBeTruthy();
    // …and not reported as done: the zone is still selected, so the bulk
    // bar still offers it.
    expect(screen.getByRole("button", { name: /^Delete 1$/ })).toBeTruthy();
  });

  it("a partly refused bulk Delete says how many, and keeps only those selected", async () => {
    const deleteZone = vi.fn((_group: unknown, id: unknown) =>
      id === ZONE.id
        ? Promise.reject(refusal(DNS_DENIED))
        : Promise.resolve({ status: 204, data: "" }),
    );
    dnsAnswers(deleteZone, [ZONE, SECOND]);
    await bulkDelete(2);

    await waitFor(() => expect(deleteZone).toHaveBeenCalledTimes(2));
    await within(topDialog()).findByText(
      /^1 of 2 zones were not deleted: Permission denied/,
    );
    expect(screen.getByRole("button", { name: /^Delete 1$/ })).toBeTruthy();
  });

  it("a bulk Delete that deleted every zone closes as done (control)", async () => {
    const deleteZone = vi.fn(() => Promise.resolve({ status: 204, data: "" }));
    dnsAnswers(deleteZone);
    await bulkDelete(1);

    await waitFor(() => expect(deleteZone).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(screen.queryByRole("button", { name: /^Delete 1$/ })).toBeNull();
  });

  it("a bulk Delete the approval queue took says so, not that it is done", async () => {
    const deleteZone = vi.fn(() =>
      Promise.resolve({
        status: 202,
        data: {
          change_request_id: "cr-1",
          state: "pending",
          preview_text: "Delete zone refused.test.",
        },
      }),
    );
    dnsAnswers(deleteZone);
    await bulkDelete(1);

    await waitFor(() => expect(deleteZone).toHaveBeenCalledTimes(1));
    await screen.findByText(/Submitted for approval/);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("Delete Zone from the zone's own menu says why", async () => {
    const deleteZone = vi.fn(() => Promise.reject(refusal(DNS_DENIED)));
    dnsAnswers(deleteZone);
    show(<DNSPage />, "/dns?group=grp-1&tab=zones");

    const name = (await screen.findAllByText(/refused\.test/)).find((el) =>
      el.closest("tr"),
    );
    fireEvent.click(name!);
    fireEvent.click(await screen.findByRole("button", { name: /^Zone$/ }));
    fireEvent.click(
      await screen.findByRole("menuitem", { name: /^Delete Zone$/ }),
    );
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: /^Continue$/ }),
    );
    fireEvent.click(within(topDialog()).getByRole("checkbox"));
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: /^Delete$/ }),
    );

    await waitFor(() => expect(deleteZone).toHaveBeenCalledTimes(1));
    await within(topDialog()).findByText(/Permission denied/);
  });
});

describe("DNS: a propagation check that could not run", () => {
  it("reads no resolver as OK, and says why the check failed", async () => {
    const checkPropagation = vi.fn(() =>
      Promise.reject(
        refusal(
          "Permission denied: need 'write' on one of ['dns_group', 'dns_zone', 'dns_record']",
        ),
      ),
    );
    answers.dnsApi = {
      defaultResolvers: async () => [
        { address: "1.1.1.1", name: "Cloudflare" },
        { address: "8.8.8.8", name: "Google" },
        { address: "9.9.9.9", name: "Quad9" },
        { address: "208.67.222.222", name: "OpenDNS" },
      ],
      checkPropagation: checkPropagation,
    };
    show(
      <PropagationCheckModal
        fqdn="www.refused.test"
        recordType="A"
        onClose={() => {}}
      />,
    );

    await screen.findByText("Cloudflare");
    await waitFor(() => expect(checkPropagation).toHaveBeenCalledTimes(1));
    // Wait for the failure to land (base: axios's message; fixed: the
    // server's detail), then read the resolver rows.
    await screen.findByText(/status code 403|Permission denied/);
    expect(screen.queryAllByText(/^OK$/)).toHaveLength(0);
    expect(screen.getByText(/Permission denied/)).toBeTruthy();
  });

  it("a check that ran shows each resolver's answer (control)", async () => {
    const resolvers = [
      { address: "1.1.1.1", name: "Cloudflare" },
      { address: "8.8.8.8", name: "Google" },
    ];
    answers.dnsApi = {
      defaultResolvers: async () => resolvers,
      checkPropagation: async () => ({
        name: "www.refused.test",
        record_type: "A",
        queried_at_ms: Date.now(),
        results: resolvers.map((r) => ({
          resolver: r.address,
          name: r.name,
          status: "ok",
          rtt_ms: 12,
          answers: ["192.0.2.81"],
          error: null,
        })),
      }),
    };
    show(
      <PropagationCheckModal
        fqdn="www.refused.test"
        recordType="A"
        onClose={() => {}}
      />,
    );

    await screen.findByText(/2 of 2 resolvers returned an answer/);
    expect(screen.getAllByText(/^OK$/)).toHaveLength(2);
  });
});

describe("DHCP: a refused server action", () => {
  function dhcpAnswers(extra: Record<string, Answer>) {
    answers.dhcpApi = {
      listGroups: async () => [DHCP_GROUP],
      listServers: async () => [DHCP_SERVER],
      ...extra,
    };
  }

  it("Pause keeps its dialog and says why", async () => {
    const pauseServer = vi.fn(() =>
      Promise.reject(
        refusal("Permission denied: need 'write' on 'dhcp_server'"),
      ),
    );
    dhcpAnswers({ pauseServer });
    show(<DHCPPage />, "/dhcp?group=dgrp-1");

    fireEvent.click(await screen.findByTitle(/^Pause — enter maintenance/));
    const dialog = topDialog();
    fireEvent.change(within(dialog).getByRole("textbox"), {
      target: { value: "patching" },
    });
    fireEvent.click(within(dialog).getByRole("button", { name: /^Pause$/ }));

    await waitFor(() => expect(pauseServer).toHaveBeenCalledTimes(1));
    await within(topDialog()).findByText(/Permission denied/);
  });

  it("Delete server keeps its dialog and says why", async () => {
    const deleteServer = vi.fn(() =>
      Promise.reject(
        refusal("Permission denied: need 'delete' on 'dhcp_server'"),
      ),
    );
    dhcpAnswers({ deleteServer });
    show(<DHCPPage />, "/dhcp?group=dgrp-1");

    fireEvent.click(await screen.findByTitle(/^Delete server$/));
    const dialog = topDialog();
    fireEvent.click(within(dialog).getByRole("checkbox"));
    fireEvent.click(within(dialog).getByRole("button", { name: /^Delete$/ }));

    await waitFor(() => expect(deleteServer).toHaveBeenCalledTimes(1));
    await within(topDialog()).findByText(/Permission denied/);
  });
});

describe("Roles: a refused delete", () => {
  it("keeps its dialog and says why", async () => {
    const del = vi.fn(() =>
      Promise.reject(refusal("Permission denied: need 'admin' on 'role'")),
    );
    answers.rolesApi = {
      list: async () => [
        {
          id: "role-1",
          name: "refused-role",
          description: "",
          is_builtin: false,
          permissions: [
            { action: "read", resource_type: "subnet", resource_id: null },
          ],
        },
      ],
      delete: del,
    };
    show(<RolesPage />, "/admin/roles");

    const row = (await screen.findByText("refused-role")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Delete" }));
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: /^Delete$/ }),
    );

    await waitFor(() => expect(del).toHaveBeenCalledTimes(1));
    await within(topDialog()).findByText(/Permission denied/);
  });
});
