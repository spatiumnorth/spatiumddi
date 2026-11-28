/**
 * @vitest-environment jsdom
 *
 * A zone name held in two views of one group draws a row per zone, in the
 * Zones tab and the sidebar tree, with the view beside it (#4843).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { DNSServerGroup, DNSZone } from "@/lib/api";

const z = (id: string, name: string, view_id: string | null) =>
  ({
    id,
    name,
    view_id,
    zone_type: "primary",
    name_scope: "",
    ttl: 3600,
    tags: {},
  }) as unknown as DNSZone;
const ZONES = [z("za", "parent.", "va"), z("zb", "parent.", "vb")];

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      listZones: () => Promise.resolve(ZONES),
      listViews: () =>
        Promise.resolve([
          { id: "va", name: "view-a" },
          { id: "vb", name: "view-b" },
        ]),
    },
  };
});

const { ZonesTab, ZoneTreeRows } = await import("./DNSPage");
const group = { id: "g1", name: "edge" } as DNSServerGroup;

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ZoneTreeRows
          groupId="g1"
          selectedZoneId={null}
          onSelectZone={() => {}}
        />
        <ZonesTab group={group} onSelectZone={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => sessionStorage.clear());
afterEach(cleanup);

describe("same zone name in two views (#4843)", () => {
  it("draws both copies in the table and the tree, labelled by view", async () => {
    mount();
    await screen.findAllByText("view: view-a", { exact: false });
    // table row + tree row per copy
    expect(screen.getAllByText("parent")).toHaveLength(4);
    expect(screen.getAllByText("view: view-a")).toHaveLength(2);
    expect(screen.getAllByText("view: view-b")).toHaveLength(2);
    // header checkbox + one per row: the table draws what select-all selects
    expect(
      document.querySelectorAll('tbody input[type="checkbox"]'),
    ).toHaveLength(2);
  });
});
