/**
 * @vitest-environment jsdom
 *
 * Edit Zone and Dynamic Updates, opened from the zone's Zone menu by the
 * keyboard, return focus to the Zone button when they close (#3485).
 *
 * Both dialogs read their row fresh before they render (#3269, #3379), so
 * they mount only after the menu has closed and its focused item has left
 * the page. The menu now hands focus to its trigger before it runs the item,
 * so the dialog records the trigger as its opener. These tests render the
 * real DNSPage and hold the fresh read until the menu is gone.
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

/** A read the test releases by hand, after the menu has closed. */
function gate<T>() {
  let release!: (v: T) => void;
  const promise = new Promise<T>((r) => (release = r));
  return { promise, release };
}

/** A browser drops focus on <body> once the focused node leaves the page;
 *  jsdom can keep the detached node as activeElement, so do it by hand. */
function dropDetachedFocus() {
  const a = document.activeElement as HTMLElement | null;
  if (a && a !== document.body && !a.isConnected) a.blur();
}

/** Zone ▸ <label> by the keyboard: Enter on the trigger, arrows to the item,
 *  then activate it (Enter on a button is a click). */
async function chooseFromZoneMenu(label: RegExp) {
  const trigger = await screen.findByRole("button", { name: /^Zone/ });
  trigger.focus();
  fireEvent.keyDown(trigger, { key: "Enter" });
  const menu = await screen.findByRole("menu");
  await waitFor(() => expect(menu.contains(document.activeElement)).toBe(true));
  for (let i = 0; i < 10; i++) {
    if ((document.activeElement?.textContent ?? "").match(label)) break;
    fireEvent.keyDown(menu, { key: "ArrowDown" });
  }
  const chosen = document.activeElement as HTMLElement;
  expect(chosen.textContent).toMatch(label);
  fireEvent.click(chosen);
  await waitFor(() => expect(screen.queryByRole("menu")).toBeNull());
  dropDetachedFocus();
  return trigger;
}

async function closeWithEscape() {
  fireEvent.keyDown(topDialog(), { key: "Escape" });
  await waitFor(() => expect(screen.queryAllByRole("dialog")).toHaveLength(0));
}

describe("dialogs from the Zone menu return focus to it (#3485)", () => {
  it("Edit Zone, after its fresh read", async () => {
    let held: ReturnType<typeof gate<unknown[]>> | null = null;
    answers.dnsApi = {
      listGroups: async () => [GROUP],
      listZones: () => (held ? held.promise : Promise.resolve(ZONES)),
      listViews: async () => [],
      listServers: async () => [],
    };
    show(<DNSPage />, "/dns?group=grp-1&zone=zone-1");
    await screen.findByRole("button", { name: /^Zone/ });

    held = gate<unknown[]>();
    const trigger = await chooseFromZoneMenu(/Edit Zone/);
    expect(screen.queryAllByRole("dialog")).toHaveLength(0);
    await act(async () => held!.release(ZONES));
    await waitFor(() => expect(topDialog().textContent).toMatch(/Edit/));

    await closeWithEscape();
    expect(document.activeElement).toBe(trigger);
  });

  it("Dynamic Updates, after its fresh read", async () => {
    const acl = gate<unknown>();
    answers.dnsApi = {
      listGroups: async () => [GROUP],
      listZones: async () => ZONES,
      listViews: async () => [],
      listServers: async () => [],
      listTSIGKeys: async () => [],
      getZoneUpdateAcl: () => acl.promise,
    };
    show(<DNSPage />, "/dns?group=grp-1&zone=zone-1");

    const trigger = await chooseFromZoneMenu(/Dynamic Updates/);
    expect(screen.queryAllByRole("dialog")).toHaveLength(0);
    await act(async () =>
      acl.release({
        zone_id: "zone-1",
        version: "v1",
        dynamic_update_enabled: false,
        driver_names: ["bind9"],
        caps: {
          supports_ip_acl: true,
          supports_tsig_acl: true,
          supports_name_scoping: true,
          supports_per_type: true,
          coarse_enum_only: false,
          supported: true,
        },
        entries: [],
        warnings: [],
      }),
    );
    await waitFor(() =>
      expect(topDialog().textContent).toMatch(/Dynamic updates/i),
    );

    await closeWithEscape();
    expect(document.activeElement).toBe(trigger);
  });
});
