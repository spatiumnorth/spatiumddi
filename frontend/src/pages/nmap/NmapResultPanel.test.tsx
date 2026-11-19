/**
 * @vitest-environment jsdom
 *
 * A sweep that found exactly one host renders the multi-host panel with
 * its Stamp button, not the single-host panel (#2581).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: async () => ({ is_superadmin: true, grants: [] }),
    },
  };
});

import type { NmapHostResult, NmapScanRead } from "@/lib/api";
import { NmapResultPanel } from "./NmapResultPanel";

const host = (address: string): NmapHostResult => ({
  address,
  hostname: null,
  host_state: "up",
  ports: [],
  os: null,
});

function scan(hosts: NmapHostResult[] | null): NmapScanRead {
  return {
    id: "s1",
    target_ip: hosts === null ? "10.0.0.5" : "10.0.0.0/29",
    preset: hosts === null ? "quick" : "subnet_sweep",
    status: "completed",
    duration_seconds: 1.2,
    summary: {
      host_state: hosts?.[0]?.host_state ?? "up",
      ports: [],
      os: null,
      hosts,
    },
  } as unknown as NmapScanRead;
}

function renderPanel(s: NmapScanRead) {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <NmapResultPanel scan={s} />
    </QueryClientProvider>,
  );
}
afterEach(cleanup);

describe("NmapResultPanel sweep shape (#2581)", () => {
  it("offers Stamp for a sweep that found one host", async () => {
    renderPanel(scan([host("10.0.0.5")]));
    await screen.findByText(/Stamp alive hosts/);
    expect(document.body.textContent).toContain("Hosts probed: 1");
  });

  it("says nothing answered for an empty sweep, with no Stamp", () => {
    renderPanel(scan([]));
    expect(document.body.textContent).toContain("No alive hosts");
    expect(document.body.textContent).not.toContain("Stamp alive hosts");
  });

  it("keeps the single-host panel for a single-address scan", () => {
    renderPanel(scan(null));
    expect(document.body.textContent).not.toContain("Hosts probed");
    expect(document.body.textContent).not.toContain("Stamp alive hosts");
  });
});
