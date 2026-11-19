/**
 * @vitest-environment jsdom
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/lib/api", () => ({
  dhcpApi: {
    listGroups: () => Promise.resolve([]),
    listOptionCodes: () => Promise.resolve([]),
    listOptionTemplates: () => Promise.resolve([]),
    listPxeProfiles: () => Promise.resolve([]),
  },
  ipamApi: {
    getSubnet: () => Promise.resolve({ id: "s", network: "10.0.0.0/24" }),
    listSubnets: () => Promise.resolve([]),
    getEffectiveSubnetDhcp: () => Promise.resolve({}),
  },
  settingsApi: { get: () => Promise.resolve({}) },
}));
vi.mock("./windowsFailover", () => ({
  GROUP_FAILOVER_QUERY_KEY: "dhcp-group-failover",
  useGroupFailover: () => ({ data: undefined }),
}));

const { CreateScopeModal } = await import("./CreateScopeModal");
afterEach(cleanup);

describe("New DHCP Scope intro (#2611)", () => {
  it("binds to a server group and names a place the sidebar has", async () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <CreateScopeModal onClose={() => {}} />
      </QueryClientProvider>,
    );
    const said =
      (await screen.findByText(/A DHCP scope binds/)).textContent ?? "";
    expect(said).toMatch(/DHCP server group/);
    expect(said).toMatch(/IPAM page/);
    expect(said).not.toMatch(/IPAM → Subnets/);
  });
});
