/**
 * @vitest-environment jsdom
 *
 * DNS zone tree groups reverse zones under collapsed folders (#4203).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { DNSZone } from "@/lib/api";

const z = (id: string, name: string) => ({ id, name }) as unknown as DNSZone;
const ZONES = [
  z("r1", "10.in-addr.arpa"),
  z("r2", "1.168.192.in-addr.arpa"),
  z("r3", "2.ip6.arpa"),
  z("f1", "example.com"),
  z("f2", "alpha.org"),
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

function mount(selected: string | null = null) {
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

describe("reverse zone folders (#4203)", () => {
  it("renders folders collapsed with counts, after the forward zones", async () => {
    const { container } = mount();
    await screen.findByText("Reverse zones (IPv4)");
    expect(screen.getByText("Reverse zones (IPv6)")).toBeTruthy();
    const v4 = screen.getByText("Reverse zones (IPv4)").closest("button")!;
    expect(v4.textContent).toContain("2");
    expect(v4.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByText("10.in-addr.arpa")).toBeNull();
    const text = container.textContent!;
    expect(text.indexOf("example.com")).toBeLessThan(
      text.indexOf("Reverse zones (IPv4)"),
    );
    expect(text.indexOf("Reverse zones (IPv4)")).toBeLessThan(
      text.indexOf("Reverse zones (IPv6)"),
    );
  });

  it("expands on click and remembers it in session state", async () => {
    mount();
    const btn = (await screen.findByText("Reverse zones (IPv4)")).closest(
      "button",
    )!;
    fireEvent.click(btn);
    expect(screen.getByText("10.in-addr.arpa")).toBeTruthy();
    expect(btn.getAttribute("aria-expanded")).toBe("true");
    cleanup();
    mount();
    await screen.findByText("10.in-addr.arpa");
    expect(screen.queryByText("2.ip6.arpa")).toBeNull();
  });

  it("opens the folder holding the selected reverse zone", async () => {
    mount("r3");
    await screen.findByText("2.ip6.arpa");
    expect(screen.queryByText("10.in-addr.arpa")).toBeNull();
  });
});
