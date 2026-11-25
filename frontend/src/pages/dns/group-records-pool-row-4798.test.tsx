/**
 * @vitest-environment jsdom
 *
 * The server group's Records tab shows a DNS pool's row read-only: a "pool"
 * pill, Edit and Delete disabled with the reason (#4798, as #4391 did for
 * the zone page's menu).
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
import { act, cleanup, render, screen, within } from "@testing-library/react";
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

const { RecordsTab } = await import("./DNSPage");

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
  zone_name: "example.com.",
  view_name: null,
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

async function open() {
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
    listGroupRecords: () =>
      Promise.resolve({ items: [plain, pooled], total: 2 }),
  };
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <RecordsTab
          group={{ id: "g1", name: "default" } as never}
          onSelectZone={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByText("192.0.2.50");
  await settle();
}

const rowOf = (v: string) => screen.getByText(v).closest("tr") as HTMLElement;

describe("group Records tab, a pool row (#4798)", { timeout: 30_000 }, () => {
  it("is read-only with a pool pill", async () => {
    await open();
    const row = rowOf("192.0.2.50");
    expect(within(row).getByText("pool")).toBeTruthy();
    expect(within(row).queryByText("user")).toBeNull();
    for (const name of ["Edit", "Delete"]) {
      const b = Array.from(row.querySelectorAll("button")).find(
        (x) => x.getAttribute("aria-label") === name,
      ) as HTMLButtonElement;
      expect(b.disabled).toBe(true);
      expect(b.title).toMatch(/Managed by a DNS pool/);
    }
  });

  it("keeps a plain row's buttons", async () => {
    await open();
    const row = rowOf("192.0.2.51");
    expect(within(row).getByText("user")).toBeTruthy();
    for (const name of ["Edit", "Delete"]) {
      const b = Array.from(row.querySelectorAll("button")).find(
        (x) => x.getAttribute("aria-label") === name,
      ) as HTMLButtonElement;
      expect(b.disabled).toBe(false);
    }
  });
});
