/**
 * @vitest-environment jsdom
 *
 * The ? sheet lists "n" (Add a record to the open zone) to exactly the users
 * whose "n" opens Add Record (#3167).
 *
 * Since #3100 the zone page's Add Record and its "n" need write on
 * dns_record (`canWriteRecords` in DNSPage.tsx), while ADD_DNS_RECORD's
 * `requires` still named write on any of dns_group, dns_zone and dns_record
 * (#3109). A role that writes zones but not records was offered a keycap
 * that does nothing. Real `usePermissions`, answered from
 * `GET /auth/me/permissions`; every API call a test does not answer stays
 * pending.
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
import type { ReactNode } from "react";
import { SHORTCUT_GROUPS } from "@/lib/shortcuts";

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

type Grant = [action: string, resourceType: string];
const VIEWER: Grant[] = [["read", "*"]];
const STAMP = "2026-10-31T00:00:00Z";
const ADD_RECORD_ROW = "Add a record to the open zone";

function signInAs(grants: Grant[]) {
  answers.authApi = {
    myPermissions: () =>
      Promise.resolve({
        is_superadmin: false,
        grants: grants.map(([action, resource_type]) => ({
          action,
          resource_type,
          resource_id: null,
        })),
      }),
  };
}

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

/** Does "n" on the open zone's page open Add Record? (the handler's gate) */
async function nOpensAddRecord(): Promise<boolean> {
  answers.dnsApi = {
    listGroups: async () => [GROUP],
    listZones: async () => [ZONE],
    listViews: async () => [],
    listServers: async () => [],
    listAcls: async () => [],
    listTSIGKeys: async () => [],
  };
  answers.dnsBlocklistApi = { list: async () => [] };
  const { DNSPage } = await import("@/pages/dns/DNSPage");
  show(<DNSPage />, "/dns?group=grp-1&tab=zones");
  const name = (await screen.findAllByText(/sheet\.test/)).find((el) =>
    el.closest("tr"),
  );
  name!.click();
  await screen.findByRole("button", { name: /Add Record/ });
  await settled();
  await act(async () => {
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "n" }));
  });
  await settled();
  return screen.queryByRole("dialog") !== null;
}

/** Does the ? sheet list the key? (the sheet's `requires`) */
async function sheetListsAddRecord(): Promise<boolean> {
  const { KeyboardShortcutsHelp } =
    await import("@/components/KeyboardShortcutsOverlay");
  show(<KeyboardShortcutsHelp />);
  await settled();
  fireEvent.click(
    screen.getByRole("button", { name: "Show keyboard shortcuts" }),
  );
  await screen.findByText("Keyboard shortcuts");
  return screen.queryByText(ADD_RECORD_ROW) !== null;
}

describe("the ? sheet and the zone page's n agree (#3167)", () => {
  it.each<[string, Grant, boolean]>([
    ["write on DNS server groups", ["write", "dns_group"], false],
    ["write on DNS zones", ["write", "dns_zone"], false],
    ["write on DNS records", ["write", "dns_record"], true],
  ])("for a role with %s", async (_label, grant, adds) => {
    signInAs([...VIEWER, grant]);
    const opens = await nOpensAddRecord();
    cleanup();
    const listed = await sheetListsAddRecord();
    expect(opens, "n on the zone page").toBe(adds);
    expect(listed, "the ? sheet lists n while n does not add a record").toBe(
      opens,
    );
  });

  it("checks every wired shortcut whose handler asks for a grant", () => {
    // A wired shortcut's handler matches via `matchesShortcut`. Global search
    // (GlobalSearch.tsx) and the sheet itself (KeyboardShortcutsOverlay.tsx)
    // answer every user, so they declare no grant; Add Record's handler asks
    // for one and is checked above. A new wired shortcut must take its place
    // here, and one that declares a grant needs a case proving it agrees.
    const wired = SHORTCUT_GROUPS.flatMap((g) => g.shortcuts).filter(
      (s) => !s.describedOnly,
    );
    expect(wired.map((s) => [s.id, s.requires ? "grant" : "everyone"])).toEqual(
      [
        ["global-search", "everyone"],
        ["show-shortcuts", "everyone"],
        ["dns-add-record", "grant"],
      ],
    );
  });
});
