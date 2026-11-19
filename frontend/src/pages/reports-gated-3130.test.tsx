/**
 * @vitest-environment jsdom
 *
 * The Reports page asks for each Top-N report only when the user holds that
 * route's read grant, and says the card is withheld when it does not,
 * instead of "Failed to load this report" (#3130). The noisiest-DNS-clients
 * report takes read on `server`, the grant the raw query log takes, so a
 * `dns_group` grant (the builtin DNS Editor's) no longer opens it.
 */
import { act, cleanup, render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const calls = {
  topSubnetsByUtilization: vi.fn(),
  topOwnersByIpCount: vi.fn(),
  topModifiedResources: vi.fn(),
  topDnsClients: vi.fn(),
};
let grants: unknown[] = [];

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: () => Promise.resolve({ is_superadmin: false, grants }),
    },
    reportsApi: calls,
  };
});

const { ReportsPage } = await import("@/pages/ReportsPage");

const empty = { generated_at: "2026-10-30T00:00:00Z", rows: [] };

beforeEach(() => {
  for (const fn of Object.values(calls)) {
    fn.mockReset();
    fn.mockResolvedValue(empty);
  }
});
afterEach(cleanup);

async function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ReportsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 300));
  });
}

describe("Reports page gates each card on its route's grant", () => {
  it("withholds the DNS clients card from a dns_group-only user", async () => {
    grants = [
      { action: "admin", resource_type: "dns_group", resource_id: null },
      { action: "read", resource_type: "subnet", resource_id: null },
    ];
    await show();
    expect(calls.topDnsClients).not.toHaveBeenCalled();
    expect(calls.topOwnersByIpCount).not.toHaveBeenCalled();
    expect(calls.topModifiedResources).not.toHaveBeenCalled();
    expect(calls.topSubnetsByUtilization).toHaveBeenCalled();
    await waitFor(() =>
      expect(document.body.textContent).toContain("No subnets yet."),
    );
    const text = document.body.textContent ?? "";
    expect(text).toContain(
      "You don't have permission to see DNS query-log clients (needs read on server).",
    );
    expect(text).not.toContain("No DNS query logs shipped yet.");
    expect(text).not.toContain("Failed to load this report.");
  });

  it("asks for the DNS clients report when the user may read server", async () => {
    grants = [{ action: "read", resource_type: "server", resource_id: null }];
    await show();
    expect(calls.topDnsClients).toHaveBeenCalled();
    await waitFor(() =>
      expect(document.body.textContent).toContain(
        "No DNS query logs shipped yet.",
      ),
    );
    const text = document.body.textContent ?? "";
    expect(text).not.toContain("needs read on server");
  });
});
