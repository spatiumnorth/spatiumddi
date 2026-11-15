/**
 * @vitest-environment jsdom
 *
 * Zones tab table: grouping rows collapse, ".arpa" starts closed, and the
 * reverse folders share the sidebar tree's state (#4203).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { DNSServerGroup, DNSZone } from "@/lib/api";

const z = (id: string, name: string) =>
  ({
    id,
    name,
    zone_type: "primary",
    name_scope: "",
    ttl: 3600,
    tags: {},
  }) as unknown as DNSZone;
const ZONES = [
  z("r1", "1.10.in-addr.arpa"),
  z("r2", "2.10.in-addr.arpa"),
  z("r3", "2.ip6.arpa"),
  z("f1", "a.example.com"),
  z("f2", "b.example.com"),
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

const { ZonesTab, ZoneTreeRows } = await import("./DNSPage");
const group = { id: "g1", name: "edge" } as DNSServerGroup;

function mount(withSidebar = false) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        {withSidebar && (
          <ZoneTreeRows
            groupId="g1"
            selectedZoneId={null}
            onSelectZone={() => {}}
          />
        )}
        <ZonesTab group={group} onSelectZone={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
const row = (t: string) => screen.getByText(t).closest("button")!;

beforeEach(() => sessionStorage.clear());
afterEach(cleanup);

describe("zones table grouping rows (#4203)", () => {
  it("starts .arpa collapsed with a count, other groups open", async () => {
    mount();
    await screen.findByText("a.example.com");
    expect(screen.getByText("b.example.com")).toBeTruthy();
    expect(row(".example.com").getAttribute("aria-expanded")).toBe("true");
    const arpa = row(".arpa");
    expect(arpa.getAttribute("aria-expanded")).toBe("false");
    expect(arpa.textContent).toContain("(3)");
    expect(screen.queryByText("1.10.in-addr.arpa")).toBeNull();
  });

  it("expands the .arpa chain and collapses another group", async () => {
    mount();
    await screen.findByText("a.example.com");
    fireEvent.click(row(".arpa"));
    expect(row(".in-addr.arpa").textContent).toContain("(2)");
    fireEvent.click(row(".in-addr.arpa"));
    expect(screen.getByText("1.10.in-addr.arpa")).toBeTruthy();
    fireEvent.click(row(".example.com"));
    expect(screen.queryByText("a.example.com")).toBeNull();
    expect(row(".example.com").textContent).toContain("(2)");
  });

  it("shares the reverse folder state with the sidebar tree", async () => {
    mount(true);
    await screen.findByText("Reverse zones (IPv4)");
    fireEvent.click(screen.getByText("Reverse zones (IPv4)"));
    fireEvent.click(row(".arpa"));
    expect(row(".in-addr.arpa").getAttribute("aria-expanded")).toBe("true");
    fireEvent.click(row(".in-addr.arpa"));
    expect(
      screen
        .getByText("Reverse zones (IPv4)")
        .closest("button")!
        .getAttribute("aria-expanded"),
    ).toBe("false");
  });

  it("holds groups open under a filter and select-all still takes every zone", async () => {
    mount();
    await screen.findByText("a.example.com");
    fireEvent.click(screen.getByTitle("Toggle filters"));
    fireEvent.change(screen.getByPlaceholderText(/name/i), {
      target: { value: "in-addr" },
    });
    await screen.findByText("1.10.in-addr.arpa");
    expect(row(".arpa").getAttribute("aria-expanded")).toBe("true");
    fireEvent.change(screen.getByPlaceholderText(/name/i), {
      target: { value: "" },
    });
    await screen.findByText("a.example.com");
    expect(screen.queryByText("1.10.in-addr.arpa")).toBeNull();
    fireEvent.click(screen.getAllByRole("checkbox")[0]);
    expect(screen.getByText(/5 selected/)).toBeTruthy();
  });
});
