/**
 * @vitest-environment jsdom
 *
 * A zone's records list shows the SOA and apex NS it serves from its settings
 * as read-only rows (#3518): badged, with no checkbox and no row action, the
 * NS rows only when the zone has none of its own, and a warning on the
 * placeholder glued to 127.0.0.1.
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
import { act, cleanup, render, screen } from "@testing-library/react";
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

const VIEWER = [{ action: "read", resource_type: "*", resource_id: null }];

const record = {
  id: "r1",
  zone_id: "z1",
  view_id: null,
  name: "www",
  fqdn: "www.example.com",
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

const apex = (over: Record<string, unknown> = {}) => ({
  driver_applies: true,
  soa: { mname: "ns1.example.com.", rname: "admin.example.com." },
  ns: ["ns1.example.com."],
  source: "placeholder",
  placeholder_glue_loopback: true,
  ...over,
});

const settle = () =>
  act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });

async function openZone(served_apex: unknown) {
  answers.authApi = {
    myPermissions: () =>
      Promise.resolve({ is_superadmin: false, grants: VIEWER }),
  };
  answers.dnsApi = {
    listRecords: () =>
      Promise.resolve({ items: [record], total: 1, served_apex }),
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
}

describe("the SOA and apex NS a zone serves (#3518)", () => {
  it("shows the placeholder NS and SOA as read-only rows with the loopback warning", async () => {
    await openZone(apex());
    const soa = screen.getByTestId("served-apex-soa");
    expect(soa.textContent).toContain("ns1.example.com. admin.example.com.");
    expect(soa.textContent).toContain("from zone settings");
    const ns = screen.getByTestId("served-apex-ns");
    expect(ns.textContent).toContain("ns1.example.com.");
    expect(ns.textContent).toContain("from zone settings");
    expect(screen.getByTestId("served-apex-warning").textContent).toContain(
      "127.0.0.1",
    );
    // Nothing selectable or editable: no checkbox, and the only control is
    // the link to Edit Zone.
    for (const row of [soa, ns]) {
      expect(row.querySelector('input[type="checkbox"]')).toBeNull();
      expect(
        Array.from(row.querySelectorAll("button")).map((b) =>
          (b.textContent ?? "").trim(),
        ),
      ).toEqual(["Edit Zone"]);
    }
    // The stored record is untouched, and still has its checkbox column.
    expect(screen.getByText("192.0.2.10")).toBeTruthy();
  });

  it("shows no NS rows, and the SOA only, when the zone declares its own NS", async () => {
    await openZone(
      apex({
        source: "declared",
        ns: ["ns-a.other.net."],
        placeholder_glue_loopback: false,
      }),
    );
    expect(screen.getByTestId("served-apex-soa")).toBeTruthy();
    expect(screen.queryByTestId("served-apex-ns")).toBeNull();
    expect(screen.queryByTestId("served-apex-warning")).toBeNull();
  });

  it("lists a Primary NS without the warning", async () => {
    await openZone(
      apex({
        source: "primary_ns",
        ns: ["ns.provider.net."],
        placeholder_glue_loopback: false,
      }),
    );
    expect(screen.getByTestId("served-apex-ns").textContent).toContain(
      "ns.provider.net.",
    );
    expect(screen.queryByTestId("served-apex-warning")).toBeNull();
  });

  it("says so, and shows no rows, where the driver does not use the rule", async () => {
    await openZone(apex({ driver_applies: false }));
    expect(screen.queryByTestId("served-apex-soa")).toBeNull();
    expect(screen.queryByTestId("served-apex-ns")).toBeNull();
    expect(screen.getByTestId("served-apex-driver-note")).toBeTruthy();
  });

  it("shows nothing when the response carries no apex", async () => {
    await openZone(null);
    expect(screen.queryByTestId("served-apex-soa")).toBeNull();
    expect(screen.queryByTestId("served-apex-driver-note")).toBeNull();
  });
});
