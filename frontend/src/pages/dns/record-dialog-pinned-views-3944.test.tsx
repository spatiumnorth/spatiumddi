/**
 * @vitest-environment jsdom
 *
 * #3944 — in a zone pinned to one view the record dialog offers the pin and the
 * unscoped default only: the record API refuses any other view (422).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const views = [
  { id: "v1", name: "view-one" },
  { id: "v2", name: "view-two" },
];
let zoneView: string | null = null;

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      listViews: async () => views,
      listZones: async () => [{ id: "z1", view_id: zoneView }],
    },
  };
});

afterEach(cleanup);

async function open(pin: string | null) {
  zoneView = pin;
  const { RecordModal } = await import("@/pages/dns/DNSPage");
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <RecordModal
          groupId="g1"
          zoneId="z1"
          zoneName="a.test."
          onClose={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByText("view-one");
}

describe("record dialog View field in a pinned zone (#3944)", () => {
  it("offers every view in an unpinned zone", async () => {
    await open(null);
    expect(screen.queryByText("view-two")).not.toBeNull();
  });
  it("offers only the pin in a pinned zone", async () => {
    await open("v1");
    expect(screen.queryByText("view-one")).not.toBeNull();
    expect(screen.queryByText("view-two")).toBeNull();
  });
});
