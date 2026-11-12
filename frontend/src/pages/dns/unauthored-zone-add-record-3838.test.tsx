/**
 * @vitest-environment jsdom
 *
 * A secondary / stub zone offers no way to add a record (#3838): the server
 * refuses a record written into a zone SpatiumDDI does not serve as primary,
 * so Add Record and the two imports are disabled with the reason.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

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

vi.setConfig({ testTimeout: 30_000 });

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const STAMP = "2026-10-31T00:00:00Z";
const GROUP = {
  id: "grp-1",
  name: "g",
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

function zone(zone_type: string) {
  return {
    id: "zone-1",
    group_id: "grp-1",
    view_id: null,
    name: "sec.test.",
    zone_type,
    kind: "forward",
    ttl: 3600,
    refresh: 86400,
    retry: 7200,
    expire: 3600000,
    minimum: 3600,
    primary_ns: "ns1.sec.test.",
    admin_email: "admin.sec.test.",
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
    masters: ["192.0.2.1"],
    tailscale_tenant_id: null,
    customer_id: null,
    name_scope: "private",
    created_at: STAMP,
    modified_at: STAMP,
  };
}

async function open(zone_type: string) {
  answers.authApi = {
    myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
  };
  answers.dnsApi = {
    listGroups: async () => [GROUP],
    listZones: async () => [zone(zone_type)],
    listViews: async () => [],
    listServers: async () => [],
    listAcls: async () => [],
    listTSIGKeys: async () => [],
  };
  answers.dnsBlocklistApi = { list: async () => [] };
  const { DNSPage } = await import("@/pages/dns/DNSPage");
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/dns?group=grp-1&tab=zones"]}>
        <DNSPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  const name = (await screen.findAllByText(/sec\.test/)).find((el) =>
    el.closest("tr"),
  );
  name!.click();
  const btn = await screen.findByRole("button", { name: /Add Record/ });
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
  return btn as HTMLButtonElement;
}

describe("Add Record on a zone SpatiumDDI does not author (#3838)", () => {
  it.each(["secondary", "stub"])(
    "is disabled with a reason on a %s zone",
    async (t) => {
      const btn = await open(t);
      expect(btn.disabled).toBe(true);
      expect(btn.title).toMatch(new RegExp(`${t} zone`));
      await act(async () => {
        fireEvent.click(screen.getByRole("button", { name: /Data/ }));
      });
      const imp = await screen.findByRole("menuitem", {
        name: /Import zone file/,
      });
      expect(
        imp.getAttribute("aria-disabled") ??
          String(imp.hasAttribute("disabled")),
      ).toBe("true");
    },
  );

  it("stays enabled on a primary zone", async () => {
    const btn = await open("primary");
    expect(btn.disabled).toBe(false);
  });
});
