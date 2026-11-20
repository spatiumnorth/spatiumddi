/**
 * @vitest-environment jsdom
 *
 * A DNS pool's record row offers no Edit… or Delete… in its right-click menu:
 * the record API always refuses them (422), so the menu says the row is
 * managed by the pool, as it does for a row IPAM manages (#4391).
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

const base = {
  zone_id: "z1",
  view_id: null,
  record_type: "A",
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
const plain = {
  ...base,
  id: "r1",
  name: "plain",
  fqdn: "plain.example.com.",
  value: "192.0.2.51",
};
const pooled = {
  ...base,
  id: "r2",
  name: "www",
  fqdn: "www.example.com.",
  value: "192.0.2.50",
  pool_member_id: "m1",
};

const settle = () =>
  act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });

async function openZone() {
  answers.authApi = {
    myPermissions: () =>
      Promise.resolve({
        is_superadmin: false,
        grants: [
          ["read", "*"],
          ["write", "dns_record"],
          ["delete", "dns_record"],
        ].map(([action, resource_type]) => ({
          action,
          resource_type,
          resource_id: null,
        })),
      }),
  };
  answers.dnsApi = {
    listRecords: () => Promise.resolve({ items: [plain, pooled], total: 2 }),
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
  await screen.findByText("192.0.2.50");
  await settle();
}

async function menuItems(value: string) {
  const row = screen.getByText(value).closest("tr") as HTMLElement;
  row.focus();
  fireEvent.contextMenu(row, { clientX: 10, clientY: 10 });
  await waitFor(
    () =>
      expect(
        document.querySelectorAll('[role="menuitem"]').length,
      ).toBeGreaterThan(0),
    { timeout: 10_000 },
  );
  return Array.from(document.querySelectorAll('[role="menuitem"]')).map(
    (i) => ({
      label: (i.textContent ?? "").trim(),
      disabled:
        i.getAttribute("aria-disabled") === "true" ||
        i.hasAttribute("data-disabled"),
      title: i.getAttribute("title"),
    }),
  );
}

describe("a pool row's right-click menu (#4391)", { timeout: 30_000 }, () => {
  it("offers no Edit or Delete, and names the pool", async () => {
    await openZone();
    const items = await menuItems("192.0.2.50");
    const labels = items.map((i) => i.label);
    expect(labels).not.toContain("Edit…");
    expect(labels).not.toContain("Delete…");
    const managed = items.find((i) => /DNS pool/.test(i.label));
    expect(managed?.disabled).toBe(true);
    expect(managed?.title).toMatch(/superadmin/);
  });

  it("keeps a plain record's Edit and Delete", async () => {
    await openZone();
    const items = await menuItems("192.0.2.51");
    const byLabel = Object.fromEntries(items.map((i) => [i.label, i.disabled]));
    expect(byLabel["Edit…"]).toBe(false);
    expect(byLabel["Delete…"]).toBe(false);
  });
});
