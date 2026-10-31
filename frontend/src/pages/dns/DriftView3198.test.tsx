/**
 * @vitest-environment jsdom
 *
 * The Drift tab never reads "In sync" for a server that transferred but is
 * not serving the zone as saved (#3198).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { DNSServerGroup, DNSZone, ZoneDriftServer } from "@/lib/api";

let servers: ZoneDriftServer[] = [];

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      getZoneDrift: () =>
        Promise.resolve({
          zone_id: "z1",
          zone_name: "example.com.",
          db_record_count: 3,
          servers,
          warnings: [],
        }),
    },
  };
});

const { DriftView } = await import("./DriftView");

afterEach(cleanup);

function server(over: Partial<ZoneDriftServer>): ZoneDriftServer {
  return {
    server_id: "s1",
    server_name: "ns1",
    driver: "bind9",
    status: "ok",
    error: null,
    reason: null,
    current_serial: 2026103104,
    target_serial: 2026103104,
    in_sync: 3,
    drift_count: 0,
    extra_on_server: [],
    missing_on_server: [],
    ...over,
  };
}

function show(s: ZoneDriftServer) {
  servers = [s];
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <DriftView
        group={{ id: "g1" } as DNSServerGroup}
        zone={{ id: "z1" } as DNSZone}
      />
    </QueryClientProvider>,
  );
}

describe("DriftView server status", () => {
  it("says Behind, not In sync, for a server that transferred but is behind", async () => {
    show(
      server({
        status: "behind",
        reason: "serving serial 2026103103, below the zone's 2026103104",
        current_serial: 2026103103,
        drift_count: 2,
        missing_on_server: [
          { name: "a", record_type: "A", value: "10.0.0.1", ttl: 300 },
          { name: "b", record_type: "A", value: "10.0.0.2", ttl: 300 },
        ],
      }),
    );
    expect(await screen.findByText("Behind")).toBeTruthy();
    expect(screen.queryByText("In sync")).toBeNull();
    expect(screen.getByText(/not serving it as saved/).textContent).toContain(
      "below the zone's 2026103104",
    );
    expect(screen.getByText(/1 of 1 comparable server drifted/)).toBeTruthy();
  });

  it("says In sync only for status ok", async () => {
    show(server({}));
    expect(await screen.findByText("In sync")).toBeTruthy();
  });

  it("does not read an unknown status as In sync", async () => {
    show(server({ status: "weird" as ZoneDriftServer["status"] }));
    expect(await screen.findByText("Unknown")).toBeTruthy();
    expect(screen.queryByText("In sync")).toBeNull();
  });
});
