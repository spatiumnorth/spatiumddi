/**
 * @vitest-environment jsdom
 *
 * Bulk allocate's Forward zone offers every forward zone of the subnet,
 * whatever its name contains, and pre-fills the subnet's primary zone
 * whichever DNS group answers first (#3079, the Bulk allocate half of #2472
 * and #2469). It waits for the zones before Preview (#3080).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { DNSZone, Subnet } from "@/lib/api";

const zone = (id: string, group_id: string, name: string) =>
  ({ id, group_id, name, kind: "forward" }) as DNSZone;

const state = {
  effective: {} as Record<string, unknown>,
  zones: {} as Record<string, Promise<DNSZone[]>>,
};

vi.mock("@/lib/api", () => ({
  formatApiError: (e: unknown) => String(e),
  ipamApi: { getEffectiveSubnetDns: () => Promise.resolve(state.effective) },
  dnsApi: { listZones: (g: string) => state.zones[g] },
}));
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

const { BulkAllocateModal } = await import("./BulkAllocateModal");

afterEach(cleanup);

function open() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <BulkAllocateModal
        subnet={{ id: "s", network: "10.98.9.0/24", name: "x" } as Subnet}
        onClose={() => {}}
      />
    </QueryClientProvider>,
  );
}

async function zoneSelect(): Promise<HTMLSelectElement> {
  const label = await screen.findByText("Forward zone", { selector: "label" });
  return label.nextElementSibling as HTMLSelectElement;
}

describe("Bulk allocate Forward zone (#3079)", () => {
  it("offers and pre-fills a primary zone whose name contains arpa", async () => {
    state.effective = {
      dns_group_ids: ["g1"],
      dns_zone_id: "zh",
      dns_additional_zone_ids: ["zp"],
    };
    state.zones = {
      g1: Promise.resolve([
        zone("zp", "g1", "plain.example."),
        zone("zh", "g1", "harpa.example."),
        zone("zr", "g1", "9.98.10.in-addr.arpa."),
      ]),
    };
    open();
    const select = await zoneSelect();
    await waitFor(() => expect(select.value).toBe("zh"));
    expect([...select.options].map((o) => o.value).sort()).toEqual([
      "zh",
      "zp",
    ]);
  });

  it("pre-fills the primary even when another group's zones answer first", async () => {
    let release: (z: DNSZone[]) => void = () => {};
    state.effective = {
      dns_group_ids: ["gS", "gP"],
      dns_zone_id: "zp",
      dns_additional_zone_ids: ["zs"],
    };
    state.zones = {
      gS: Promise.resolve([zone("zs", "gS", "s.test.")]),
      gP: new Promise<DNSZone[]>((r) => (release = r)),
    };
    open();
    await screen.findByText("Forward zone", { selector: "label" });
    // Preview waits for the primary's group.
    const preview = screen.getByRole("button", {
      name: "Preview",
    }) as HTMLButtonElement;
    expect(preview.disabled).toBe(true);
    release([zone("zp", "gP", "p.test.")]);
    const select = await zoneSelect();
    await waitFor(() => expect(select.value).toBe("zp"));
    await waitFor(() => expect(preview.disabled).toBe(false));
  });
});
