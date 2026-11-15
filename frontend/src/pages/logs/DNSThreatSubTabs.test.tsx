/**
 * @vitest-environment jsdom
 *
 * Logs → DNS Threat: one table at a time under three sub-tabs, each with
 * its row count, selection kept in session state (#4172).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const win = {
  id: "w1",
  client_ip: "192.0.2.99",
  window_start: "2026-10-22T10:00:00Z",
  window_end: "2026-10-22T11:00:00Z",
  query_count: 100,
  distinct_qnames: 90,
  distinct_parents: 1,
  top_parent: "evil.example",
  top_parent_subdomains: 90,
  max_label_length: 50,
  mean_label_entropy: 4,
  payload_qtype_count: 1,
  tunnel_score: 90,
  tunnel_signals: [],
  beacon_score: 0,
  beacon_candidates: [],
  beacon_detail: "",
  dga_score: 0,
  dga_candidates: [],
  dga_signals: [],
  dga_detail: "",
  allowlisted: false,
  server_count: 1,
  muted: false,
  mute_reason: null,
};
const offender = (ip: string) => ({
  client_ip: ip,
  hits: 5,
  distinct_names: 2,
  top_qname: "ads.example",
  last_seen: "2026-10-22T10:00:00Z",
  noisy: false,
});
const hit = (id: string) => ({
  id,
  ts: "2026-10-22T10:00:00Z",
  client_ip: "192.0.2.5",
  qname: `${id}.blocked.example`,
  trigger: "QNAME",
  policy: "NXDOMAIN",
  rpz_zone: "feed.rpz",
});

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      me: async () => ({ is_superadmin: true }),
      myPermissions: async () => ({ is_superadmin: true, grants: [] }),
    },
    dnsThreatApi: {
      listWindows: async () => [win],
      summary: async () => ({
        has_data: true,
        windows_scored: 1,
        clients_seen: 1,
      }),
      listMutes: async () => [],
      rpzSummary: async () => ({
        has_data: true,
        blocked_hits: 9,
        clients_blocked: 2,
        distinct_names: 3,
        passthru_hits: 0,
      }),
      rpzClients: async () => [offender("192.0.2.5"), offender("192.0.2.6")],
      rpzHits: async () => [hit("a"), hit("b"), hit("c")],
    },
  };
});

import { DNSThreatTab } from "./DNSThreatTab";

function renderTab() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>
        <DNSThreatTab />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => sessionStorage.clear());
afterEach(cleanup);

describe("DNS Threat sub-tabs (#4172)", () => {
  it("renders the three sub-tabs with their counts", async () => {
    renderTab();
    const threat = await screen.findByRole("tab", { name: /Threat log\s*1/ });
    expect(threat.getAttribute("aria-selected")).toBe("true");
    expect(
      await screen.findByRole("tab", { name: /RPZ hits\s*2/ }),
    ).toBeTruthy();
    expect(
      await screen.findByRole("tab", { name: /Recent blocked\s*3/ }),
    ).toBeTruthy();
  });

  it("shows one table at a time", async () => {
    renderTab();
    await screen.findByText("192.0.2.99");
    expect(
      screen.queryByText("Clients reaching for blocked domains"),
    ).toBeNull();

    fireEvent.click(await screen.findByRole("tab", { name: /RPZ hits/ }));
    await screen.findByText("Clients reaching for blocked domains");
    expect(screen.queryByText("192.0.2.99")).toBeNull();
    expect(screen.queryByText("a.blocked.example")).toBeNull();

    fireEvent.click(screen.getByRole("tab", { name: /Recent blocked/ }));
    await screen.findByText("a.blocked.example");
    expect(
      screen.queryByText("Clients reaching for blocked domains"),
    ).toBeNull();
  });

  it("remembers the selection in session state", async () => {
    renderTab();
    fireEvent.click(await screen.findByRole("tab", { name: /Recent blocked/ }));
    await screen.findByText("a.blocked.example");
    cleanup();
    renderTab();
    const tab = await screen.findByRole("tab", { name: /Recent blocked/ });
    expect(tab.getAttribute("aria-selected")).toBe("true");
    await screen.findByText("a.blocked.example");
  });
});
