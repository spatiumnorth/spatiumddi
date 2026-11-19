/**
 * @vitest-environment jsdom
 *
 * The Zone menu's Delegate item is disabled, with the server's reason, when the
 * zone's nearest parent is a secondary or stub zone (#4258); it is enabled when
 * the preview has a primary parent with records to create.
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

async function open(preview: unknown) {
  answers.authApi = {
    myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
  };
  answers.dnsApi = {
    listGroups: async () => [GROUP],
    listZones: async () => [zone("primary")],
    getDelegationPreview: async () => preview,
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
  await screen.findByRole("button", { name: /Add Record/ });
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /^Zone/ }));
  });
  return screen.queryByRole("menuitem", { name: /Delegate/ });
}

describe("Delegate on a zone whose parent is not primary (#4258)", () => {
  it("is disabled with the reason for a secondary parent", async () => {
    const reason =
      "The parent zone corp.test is a secondary zone, served from its masters.";
    const item = await open({
      has_parent: false,
      parent_zone_name: "corp.test.",
      reason,
    });
    expect(item).not.toBeNull();
    expect(
      item!.getAttribute("aria-disabled") ??
        String(item!.hasAttribute("disabled")),
    ).toBe("true");
    expect(item!.getAttribute("title")).toBe(reason);
  });

  it("is absent when there is no parent at all", async () => {
    expect(await open({ has_parent: false })).toBeNull();
  });

  it("is offered for a primary parent with records to create", async () => {
    const item = await open({
      has_parent: true,
      parent_zone_id: "p",
      parent_zone_name: "corp.test.",
      child_zone_id: "zone-1",
      child_zone_name: "sec.test.",
      child_label: "sec",
      ns_records_to_create: [
        { name: "sec", record_type: "NS", value: "ns1.", ttl: null },
      ],
      glue_records_to_create: [],
      existing_ns_records: [],
      existing_glue_records: [],
      warnings: [],
      child_apex_ns_count: 1,
    });
    expect(item).not.toBeNull();
    expect(item!.getAttribute("aria-disabled")).not.toBe("true");
  });
});
