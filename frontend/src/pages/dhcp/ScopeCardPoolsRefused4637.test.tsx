/**
 * @vitest-environment jsdom
 *
 * #4637 — the built-in Auditor and Compliance Editor read DHCP scopes but not
 * pools, so a scope card's pool read is refused. The card said "0 pools" and
 * "Pools (0)" for a scope that holds one; it now says the pools cannot be
 * seen, and a reader who may read them still sees the count and the row.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const poolsAnswer = vi.fn();

vi.mock("@/lib/api", () => ({
  authApi: {
    myPermissions: () => Promise.resolve({ is_superadmin: false, grants: [] }),
  },
  dhcpApi: {
    listScopesBySubnet: () =>
      Promise.resolve([
        {
          id: "scope-1",
          name: "staff",
          subnet_id: "sub-1",
          group_id: "grp-1",
          address_family: "ipv4",
          lease_time: 86400,
          enabled: true,
          ddns_enabled: false,
        },
      ]),
    listGroups: () => Promise.resolve([]),
    listStatics: () => Promise.resolve([]),
    listPools: () => poolsAnswer(),
  },
  formatApiError: (_e: unknown, fb: string) => fb,
}));
vi.mock("./WindowsFailoverPanel", () => ({ ScopeServingStrip: () => null }));
vi.mock("./CreateScopeModal", () => ({ CreateScopeModal: () => null }));
vi.mock("./CreatePoolModal", () => ({ CreatePoolModal: () => null }));

const { DHCPSubnetPanel } = await import("./DHCPSubnetPanel");

function refused() {
  return Object.assign(new Error("Request failed with status code 403"), {
    isAxiosError: true,
    response: {
      status: 403,
      data: { detail: "Permission denied: need 'read' on 'dhcp_pool'" },
    },
  });
}

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <DHCPSubnetPanel subnetId="sub-1" />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("scope card pools read (#4637)", () => {
  it("a refused pool read is told, never drawn as 0 pools", async () => {
    poolsAnswer.mockImplementation(() => Promise.reject(refused()));
    mount();
    expect(
      await screen.findByText(
        /don't have permission to see this scope's pools/,
      ),
    ).toBeTruthy();
    expect(screen.queryByText(/0 pools/)).toBeNull();
    expect(screen.queryByText(/Pools \(0\)/)).toBeNull();
  });

  it("a reader who can read pools still sees the count and the row", async () => {
    poolsAnswer.mockImplementation(() =>
      Promise.resolve([
        {
          id: "p1",
          name: "default",
          start_ip: "10.0.0.10",
          end_ip: "10.0.0.20",
          pool_type: "dynamic",
        },
      ]),
    );
    mount();
    expect(await screen.findByText("10.0.0.10")).toBeTruthy();
    expect(screen.getByText(/· 1 pool$/)).toBeTruthy();
    expect(screen.getByText("Pools (1)")).toBeTruthy();
  });

  it("a scope with no pools still says 0 pools", async () => {
    poolsAnswer.mockImplementation(() => Promise.resolve([]));
    mount();
    expect(await screen.findByText(/· 0 pools/)).toBeTruthy();
    expect(screen.getByText("Pools (0)")).toBeTruthy();
  });
});
