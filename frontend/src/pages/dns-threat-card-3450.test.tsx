/**
 * @vitest-environment jsdom
 *
 * The Security tab's DNS tunneling card needs read on servers (#3450): a
 * user without it must not ask the summary (each ask a 403 and a denied
 * audit row, every 60 s), and the card says why it is missing.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const summary = vi.fn();
let grants: { action: string; resource_type: string }[] = [];

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: () =>
        Promise.resolve({
          is_superadmin: false,
          grants: grants.map((g) => ({ ...g, resource_id: null })),
        }),
    },
    dnsThreatApi: {
      ...actual.dnsThreatApi,
      summary: (...a: unknown[]) => summary(...a),
    },
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

import { DNSThreatCard } from "./DashboardPage";

afterEach(() => {
  cleanup();
  summary.mockReset();
});

async function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <DNSThreatCard />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
}

describe("DNSThreatCard permission gate (#3450)", () => {
  it("does not ask the summary without read on servers, and says why", async () => {
    grants = [
      { action: "write", resource_type: "subnet" },
      { action: "read", resource_type: "dns_zone" },
    ];
    await show();
    expect(summary).not.toHaveBeenCalled();
    expect(
      screen.getByText(/needs read on DNS servers|read on DNS servers/),
    ).toBeTruthy();
  });

  it("asks the summary with read on servers", async () => {
    grants = [{ action: "read", resource_type: "server" }];
    summary.mockResolvedValue({
      has_data: true,
      suspicious_clients: 0,
      clients_seen: 3,
      worst_client_ip: null,
      worst_client_score: null,
      worst_client_parent: null,
    });
    await show();
    expect(summary).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(/read on DNS servers/)).toBeNull();
  });
});
