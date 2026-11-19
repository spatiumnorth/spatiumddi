/**
 * @vitest-environment jsdom
 *
 * A zone selected by deep link opens its folder and every ancestor row (#4203).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { DNSZone } from "@/lib/api";

const z = (id: string, name: string) => ({ id, name }) as unknown as DNSZone;
const ZONES = [
  z("a", "10.in-addr.arpa"),
  z("b", "192.in-addr.arpa"),
  z("c", "168.192.in-addr.arpa"),
  z("d", "7.168.192.in-addr.arpa"),
  z("e", "f.ip6.arpa"),
  z("f", "d.f.ip6.arpa"),
  z("g", "example.com"),
];

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      listZones: () => Promise.resolve(ZONES),
      listViews: () => Promise.resolve([]),
    },
  };
});

const { ZoneTreeRows } = await import("./DNSPage");

function mount(selected: string | null) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ZoneTreeRows
        groupId="g1"
        selectedZoneId={selected}
        onSelectZone={() => {}}
      />
    </QueryClientProvider>,
  );
}

beforeEach(() => sessionStorage.clear());
afterEach(cleanup);

describe("deep link opens every ancestor row (#4203)", () => {
  it("first-level reverse zone: folder opens, zone visible", async () => {
    mount("a");
    await screen.findByText("10.in-addr.arpa");
    expect(screen.queryByText("7.168.192.in-addr.arpa")).toBeNull();
  });

  it("third-level IPv4 zone shows with its parents expanded", async () => {
    mount("d");
    await screen.findByText("7.168.192.in-addr.arpa");
    expect(screen.getByText("168.192.in-addr.arpa")).toBeTruthy();
    expect(screen.getByText("192.in-addr.arpa")).toBeTruthy();
  });

  it("nested ip6.arpa zone shows with its parent expanded", async () => {
    mount("f");
    await screen.findByText("d.f.ip6.arpa");
    expect(screen.getByText("f.ip6.arpa")).toBeTruthy();
  });

  it("keeps rows the operator already had open", async () => {
    sessionStorage.setItem(
      "spatium.dns.expandedZones.g1",
      JSON.stringify(["reverse:ipv6", "f.ip6.arpa"]),
    );
    mount("d");
    await screen.findByText("7.168.192.in-addr.arpa");
    expect(screen.getByText("d.f.ip6.arpa")).toBeTruthy();
  });
});
