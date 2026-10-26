/**
 * @vitest-environment jsdom
 *
 * A quick reopen of Edit Group / Edit Zone, before the post-save refetch has
 * resolved, shows what was saved, and an untouched Save keeps it (#2830).
 *
 * The page kept the zone / group object it had when the tree was clicked, so
 * a reopened dialog was seeded with the pre-save values and the next Save
 * wrote them back. These tests render the real DNSPage over a small in-memory
 * API that stores what updateZone / updateGroup send.
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
/** Per API object, the calls a test answers. Anything else stays pending,
 *  so no test here ever reaches the network. */
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

// A superadmin: Edit Group is superadmin-only.
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

const STAMP = "2026-10-15T00:00:00Z";

const GROUP = {
  id: "grp-1",
  name: "corp",
  description: "",
  group_type: "internal",
  default_view: null,
  is_recursive: false,
  catalog_zones_enabled: false,
  catalog_zone_name: "",
  server_drivers: [],
  created_at: STAMP,
  modified_at: STAMP,
};

function zone(id: string, name: string) {
  return {
    id,
    group_id: "grp-1",
    view_id: null,
    name,
    zone_type: "primary",
    kind: "forward",
    ttl: 3600,
    refresh: 86400,
    retry: 7200,
    expire: 3600000,
    minimum: 3600,
    primary_ns: "ns1.example.com.",
    admin_email: "hostmaster.example.com.",
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
    created_at: STAMP,
    modified_at: STAMP,
  };
}

const ZONES = [zone("zone-1", "example.com."), zone("zone-2", "example.net.")];

function show(ui: ReactNode, url: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

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

/** An API that stores what the dialogs save. Until a save has gone
 *  through, list reads answer; afterwards (the post-save refetch) never resolves, so the dialog can
 *  only learn the saved values from the PUT's response. */
function storingApi() {
  const store = {
    group: { ...GROUP, is_recursive: true },
    zone: { ...ZONES[0] },
    saved: [] as Record<string, unknown>[],
  };
  answers.dnsApi = {
    listGroups: () =>
      store.saved.length === 0
        ? Promise.resolve([{ ...store.group }])
        : new Promise(() => {}),
    listZones: () =>
      store.saved.length === 0
        ? Promise.resolve([{ ...store.zone }, ZONES[1]])
        : new Promise(() => {}),
    listViews: async () => [],
    listServers: async () => [],
    updateZone: async (_g: unknown, _z: unknown, d: unknown) => {
      store.saved.push(d as Record<string, unknown>);
      Object.assign(store.zone, d);
      return { ...store.zone };
    },
    updateGroup: async (_g: unknown, d: unknown) => {
      store.saved.push(d as Record<string, unknown>);
      Object.assign(store.group, d);
      return { ...store.group };
    },
  };
  return store;
}

describe("Edit Zone reopened before the refetch resolves (#2830)", () => {
  it("shows the saved TTL, and an untouched Save sends it", async () => {
    const store = storingApi();
    show(<DNSPage />, "/dns?group=grp-1&zone=zone-1");

    async function openEditZone() {
      fireEvent.click(await screen.findByRole("button", { name: /^Zone/ }));
      fireEvent.click(
        await screen.findByRole("menuitem", { name: /Edit Zone/ }),
      );
      return (
        await within(topDialog()).findByText("Default TTL (seconds)", {
          selector: "label",
        })
      ).nextElementSibling as HTMLInputElement;
    }

    const ttl = await openEditZone();
    fireEvent.change(ttl, { target: { value: "300" } });
    fireEvent.click(within(topDialog()).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(store.zone.ttl).toBe(300));
    await waitFor(() =>
      expect(screen.queryAllByRole("dialog")).toHaveLength(0),
    );

    const again = await openEditZone();
    expect(again.value).toBe("300");
    fireEvent.click(within(topDialog()).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(store.saved).toHaveLength(2));
    expect(store.saved[1]).toMatchObject({ ttl: 300 });
  });
});

describe("Edit Group reopened before the refetch resolves (#2830)", () => {
  it("shows Allow recursion off, and an untouched Save sends is_recursive false", async () => {
    const store = storingApi();
    show(<DNSPage />, "/dns?group=grp-1");

    async function openEditGroup() {
      fireEvent.click(
        await screen.findByRole("button", { name: /Edit Group/ }),
      );
      return within(topDialog()).getByText("Allow recursion")
        .previousElementSibling as HTMLInputElement;
    }

    const box = await openEditGroup();
    expect(box.checked).toBe(true);
    fireEvent.click(box);
    fireEvent.click(within(topDialog()).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(store.group.is_recursive).toBe(false));
    await waitFor(() =>
      expect(screen.queryAllByRole("dialog")).toHaveLength(0),
    );

    const again = await openEditGroup();
    expect(again.checked).toBe(false);
    fireEvent.click(within(topDialog()).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(store.saved).toHaveLength(2));
    expect(store.saved[1]).toMatchObject({ is_recursive: false });
    expect(store.group.is_recursive).toBe(false);
  });
});
