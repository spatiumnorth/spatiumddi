/**
 * @vitest-environment jsdom
 *
 * Delete Zone says what the delete does (#1880).
 *
 * The single and bulk zone deletes said the zone and its records would be
 * "permanently deleted" ("Confirm Permanent Deletion", "This action cannot
 * be undone"), while the console sends the soft delete and the zone goes to
 * Trash. These tests render the real DNSPage as a DNS Editor (not a
 * superadmin), walk each dialog through both steps, read what the operator
 * reads, and check what is sent: the soft delete, with no `permanent`.
 *
 * Restoring from Trash is superadmin-only server-side, so the copy must not
 * tell a DNS Editor that they can restore the zone themselves.
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

// A DNS Editor: every DNS permission, not a superadmin.
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: false,
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

function words(el: HTMLElement): string {
  return (el.textContent ?? "").replace(/\s+/g, " ").trim();
}

const CLAIMS_PERMANENT = /permanent|cannot be undone|for good/i;
/** Restoring is superadmin-only, so the dialog may not promise the
 *  operator ("you") that they can restore it. */
const PROMISES_SELF_RESTORE = /\byou can restore\b/i;

function expectSaysTrash(said: string) {
  expect(said, `the dialog never says Trash: "${said}"`).toMatch(/\bTrash\b/);
  expect(
    said,
    "the console sends the soft delete, so the dialog must not say it is permanent",
  ).not.toMatch(CLAIMS_PERMANENT);
  expect(said).not.toMatch(PROMISES_SELF_RESTORE);
  expect(said, "names who can restore it").toMatch(/superadmin/i);
}

function dnsAnswers(extra: Record<string, Answer> = {}) {
  answers.dnsApi = {
    listGroups: async () => [GROUP],
    listZones: async () => ZONES,
    listViews: async () => [],
    listServers: async () => [],
    ...extra,
  };
}

afterEach(() => {
  cleanup();
  for (const k of Object.keys(answers)) delete answers[k];
  localStorage.clear();
  sessionStorage.clear();
});

describe("Delete Zone (zone detail)", () => {
  it("says Trash at both steps and sends the soft delete", async () => {
    const deleteZone = vi.fn(async (..._args: unknown[]) => ({ status: 204 }));
    dnsAnswers({ deleteZone });
    show(<DNSPage />, "/dns?group=grp-1&zone=zone-1");

    fireEvent.click(await screen.findByRole("button", { name: /^Zone/ }));
    fireEvent.click(
      await screen.findByRole("menuitem", { name: /Delete Zone/ }),
    );

    const step1 = words(topDialog());
    expect(step1).toContain("example.com.");
    expectSaysTrash(step1);

    fireEvent.click(
      within(topDialog()).getByRole("button", { name: /^Continue$/ }),
    );
    const step2 = words(topDialog());
    expectSaysTrash(step2);

    const confirm = within(topDialog()).getByRole("button", {
      name: /Move to Trash/,
    });
    expect(
      (confirm as HTMLButtonElement).disabled,
      "the confirm checkbox gates the delete",
    ).toBe(true);
    fireEvent.click(within(topDialog()).getByRole("checkbox"));
    fireEvent.click(confirm);

    await waitFor(() => expect(deleteZone).toHaveBeenCalledTimes(1));
    expect(deleteZone.mock.calls[0]).toEqual(["grp-1", "zone-1"]);
  });
});

describe("bulk zone delete (zones list)", () => {
  it("says Trash at both steps and soft-deletes each zone", async () => {
    const deleteZone = vi.fn(async (..._args: unknown[]) => ({ status: 204 }));
    dnsAnswers({ deleteZone });
    show(<DNSPage />, "/dns?group=grp-1&tab=zones");

    // Select both zones with the list's select-all checkbox.
    fireEvent.click(await screen.findByLabelText("Select all filtered zones"));

    fireEvent.click(await screen.findByRole("button", { name: /^Delete 2$/ }));

    const step1 = words(topDialog());
    expectSaysTrash(step1);
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: /^Continue$/ }),
    );
    const step2 = words(topDialog());
    expectSaysTrash(step2);
    expect(step2).toMatch(
      /2 zones and all their records will be moved to Trash/,
    );

    fireEvent.click(within(topDialog()).getByRole("checkbox"));
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: /Move to Trash/ }),
    );

    await waitFor(() => expect(deleteZone).toHaveBeenCalledTimes(2));
    expect(deleteZone.mock.calls.map((c) => c.length)).toEqual([2, 2]);
  });
});

describe("the request dnsApi.deleteZone sends", () => {
  it("is the soft delete: no permanent flag", async () => {
    // The real client, with an axios adapter in place of the network.
    const real = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
    let seen: { method?: string; url?: string; params?: unknown } = {};
    const original = real.api.defaults.adapter;
    real.api.defaults.adapter = ((config: typeof seen) => {
      seen = config;
      return Promise.resolve({
        data: {},
        status: 204,
        statusText: "",
        headers: {},
        config,
      });
    }) as never;
    try {
      await real.dnsApi.deleteZone("g1", "z1");
    } finally {
      real.api.defaults.adapter = original;
    }
    expect(seen.method).toBe("delete");
    expect(seen.url).toBe("/dns/groups/g1/zones/z1");
    expect(JSON.stringify(seen.params ?? {})).not.toMatch(/permanent/);
  });
});
