/**
 * @vitest-environment jsdom
 *
 * Inside a zone, a record's right-click Edit… and Delete… are disabled for a
 * user who may not write or delete DNS records, and say why, as the row's own
 * Edit and Delete buttons and the IPAM tree's right-click items do (#3421,
 * after #3392). A writer's items stay enabled.
 */

import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";
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

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    modules: [],
    ready: true,
    isLoading: false,
    isError: false,
    refetch: () => {},
    enabled: () => true,
  }),
}));

const { ZoneDetailView } = await import("./DNSPage");

vi.setConfig({ testTimeout: 30_000 });

// What Radix's menu needs from jsdom (as components/ui/context-menu.test.tsx).
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver;
Element.prototype.scrollIntoView ??= () => {};
const realMatches = Element.prototype.matches;
beforeAll(() => {
  Element.prototype.matches = function (sel: string) {
    if (sel === ":popover-open" || sel === ":modal") return false;
    return realMatches.call(this, sel);
  };
});
afterAll(() => {
  Element.prototype.matches = realMatches;
});

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const STAMP = "2026-11-03T00:00:00Z";
const NEEDS_WRITE = "Requires write permission on DNS records";
const NEEDS_DELETE = "Requires delete permission on DNS records";

type Grant = [string, string];
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
const VIEWER: Grant[] = [["read", "*"]];

const record = {
  id: "r1",
  zone_id: "z1",
  view_id: null,
  name: "www",
  fqdn: "www.example.com.",
  record_type: "A",
  value: "192.0.2.10",
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

const settle = () =>
  act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });

/** The zone's records table; the record's row. */
async function openZone() {
  answers.dnsApi = {
    listRecords: () => Promise.resolve({ items: [record], total: 1 }),
  };
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ZoneDetailView
          group={{ id: "g1", name: "default", driver: "bind9" } as never}
          zone={
            {
              id: "z1",
              group_id: "g1",
              name: "example.com.",
              zone_type: "primary",
              view_id: null,
            } as never
          }
          onDeleted={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByText("192.0.2.10");
  await settle();
  return screen.getByText("192.0.2.10").closest("tr") as HTMLElement;
}

/** Right-click `row`; the open menu as {label: disabled}. */
async function menuItems(row: HTMLElement) {
  row.focus();
  fireEvent.contextMenu(row, { clientX: 10, clientY: 10 });
  await waitFor(() =>
    expect(
      document.querySelectorAll('[role="menuitem"]').length,
    ).toBeGreaterThan(0),
  );
  return Object.fromEntries(
    Array.from(document.querySelectorAll('[role="menuitem"]')).map((i) => [
      (i.textContent ?? "").trim(),
      i.getAttribute("aria-disabled") === "true" ||
        i.hasAttribute("data-disabled"),
    ]),
  );
}
const item = (label: string) =>
  Array.from(document.querySelectorAll('[role="menuitem"]')).find(
    (i) => (i.textContent ?? "").trim() === label,
  ) as HTMLElement;

describe("a record's right-click menu (#3421)", () => {
  it("disables a Viewer's Edit and Delete with their reasons, as the row's buttons", async () => {
    signInAs(VIEWER);
    const row = await openZone();
    // The row's own Edit and Delete buttons already give these reasons.
    const inline = Array.from(row.querySelectorAll("button")).map(
      (b) => b.title,
    );
    expect(inline).toContain(NEEDS_WRITE);
    expect(inline).toContain(NEEDS_DELETE);

    const m = await menuItems(row);
    expect(m["Copy Name"]).toBe(false);
    expect(m["Copy Value"]).toBe(false);
    expect(m["Edit…"]).toBe(true);
    expect(m["Delete…"]).toBe(true);
    expect(item("Edit…").getAttribute("title")).toBe(NEEDS_WRITE);
    expect(item("Delete…").getAttribute("title")).toBe(NEEDS_DELETE);
    // The reason is only seen on hover if the item takes pointer events.
    expect(item("Edit…").className).not.toMatch(/pointer-events-none/);

    fireEvent.click(item("Edit…"));
    fireEvent.click(item("Delete…"));
    await settle();
    expect(document.querySelector('[role="dialog"]')).toBeNull();
  });

  it("gives each item its own gate: write without delete keeps Edit, not Delete", async () => {
    signInAs([
      ["read", "*"],
      ["write", "dns_record"],
    ]);
    const m = await menuItems(await openZone());
    expect(m["Edit…"]).toBe(false);
    expect(item("Edit…").hasAttribute("title")).toBe(false);
    expect(m["Delete…"]).toBe(true);
    expect(item("Delete…").getAttribute("title")).toBe(NEEDS_DELETE);
  });

  it("keeps a writer's Edit and Delete enabled, with no reason", async () => {
    signInAs([
      ["read", "*"],
      ["write", "dns_record"],
      ["delete", "dns_record"],
    ]);
    const m = await menuItems(await openZone());
    expect(m["Edit…"]).toBe(false);
    expect(m["Delete…"]).toBe(false);
    expect(item("Edit…").hasAttribute("title")).toBe(false);
    expect(item("Delete…").hasAttribute("title")).toBe(false);
    fireEvent.click(item("Edit…"));
    await waitFor(() =>
      expect(document.querySelector('[role="dialog"]')).toBeTruthy(),
    );
  });
});
