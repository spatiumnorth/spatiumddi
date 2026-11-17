/**
 * @vitest-environment jsdom
 *
 * Deleting a DNS record offers Move to Trash or Delete permanently in the
 * same modal IPAM uses (#4078). The permanent choice is superadmin-only
 * server-side, so it is offered to superadmins only; the call sends
 * `permanent=true`.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

type Answer = (...args: unknown[]) => unknown;
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

vi.mock("@/hooks/useFeatureModules", async () => {
  const actual = await vi.importActual<
    typeof import("@/hooks/useFeatureModules")
  >("@/hooks/useFeatureModules");
  return {
    ...actual,
    useFeatureModules: () => ({ ready: true, enabled: () => true }),
  };
});

// Two pages per case, the zone's and the sheet's.
vi.setConfig({ testTimeout: 30_000 });

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const STAMP = "2026-10-31T00:00:00Z";

function show(ui: ReactNode, url = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Let the permission answer land: every gate is closed while it loads. */
async function settled() {
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
}

const GROUP = {
  id: "grp-1",
  name: "sheet-walk",
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
  name: "sheet.test.",
  zone_type: "primary",
  kind: "forward",
  ttl: 3600,
  refresh: 86400,
  retry: 7200,
  expire: 3600000,
  minimum: 3600,
  primary_ns: "ns1.sheet.test.",
  admin_email: "admin.sheet.test.",
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

function signInSuper(isSuper: boolean) {
  answers.authApi = {
    myPermissions: () =>
      Promise.resolve({
        is_superadmin: isSuper,
        grants: isSuper
          ? []
          : [
              { action: "read", resource_type: "*", resource_id: null },
              {
                action: "delete",
                resource_type: "dns_record",
                resource_id: null,
              },
            ],
      }),
  };
}

const REC = {
  id: "rec-1",
  zone_id: "zone-1",
  view_id: null,
  name: "www",
  fqdn: "www.sheet.test.",
  record_type: "A",
  value: "192.0.2.1",
  ttl: null,
  priority: null,
  weight: null,
  port: null,
  auto_generated: false,
  tailscale_tenant_id: null,
  pool_member_id: null,
  created_at: STAMP,
  modified_at: STAMP,
};

async function openDeleteModal(deleteRecord: Answer) {
  answers.dnsApi = {
    listGroups: async () => [GROUP],
    listZones: async () => [ZONE],
    listViews: async () => [],
    listServers: async () => [],
    listAcls: async () => [],
    listTSIGKeys: async () => [],
    listRecords: async () => ({
      items: [REC],
      total: 1,
      page: 1,
      page_size: 100,
    }),
    deleteRecord,
  };
  answers.dnsBlocklistApi = { list: async () => [] };
  const { DNSPage } = await import("@/pages/dns/DNSPage");
  show(<DNSPage />, "/dns?group=grp-1&tab=zones");
  const name = (await screen.findAllByText(/sheet\.test/)).find((el) =>
    el.closest("tr"),
  );
  name!.click();
  await screen.findByText("192.0.2.1");
  await settled();
  fireEvent.click(await screen.findByRole("button", { name: "Delete record" }));
  await screen.findByText("Move to Trash (reversible)");
}

describe("DNS record delete: Trash or permanently (#4078)", () => {
  it("a superadmin sees both choices; Delete Permanently sends permanent=true", async () => {
    signInSuper(true);
    const del = vi.fn(async () => ({}));
    await openDeleteModal(del);
    fireEvent.click(screen.getByRole("button", { name: "Delete Permanently" }));
    await waitFor(() => expect(del).toHaveBeenCalled());
    expect(del).toHaveBeenCalledWith("grp-1", "zone-1", "rec-1", {
      permanent: true,
    });
  });

  it("Move to Trash is the soft call", async () => {
    signInSuper(true);
    const del = vi.fn(async () => ({}));
    await openDeleteModal(del);
    fireEvent.click(screen.getByRole("button", { name: "Move to Trash" }));
    await waitFor(() => expect(del).toHaveBeenCalled());
    expect(del).toHaveBeenCalledWith("grp-1", "zone-1", "rec-1", {
      permanent: false,
    });
  });

  it("a non-superadmin sees Move to Trash only", async () => {
    signInSuper(false);
    await openDeleteModal(vi.fn(async () => ({})));
    expect(screen.getByRole("button", { name: "Move to Trash" })).toBeTruthy();
    expect(
      screen.queryByRole("button", { name: "Delete Permanently" }),
    ).toBeNull();
    expect(screen.queryByText(/irreversible/)).toBeNull();
  });
});
