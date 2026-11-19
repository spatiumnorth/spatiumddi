/**
 * @vitest-environment jsdom
 *
 * #2479 — Edit DHCP Scope must not offer a server-group picker the API
 * cannot honour: the stored group is shown read-only and no select exists.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { DHCPScope } from "@/lib/api";

vi.mock("@/lib/api", () => ({
  dhcpApi: {
    listGroups: () =>
      Promise.resolve([
        { id: "g-a", name: "group-a", mode: "standalone" },
        { id: "g-b", name: "group-b", mode: "standalone" },
      ]),
    listOptionCodes: () => Promise.resolve([]),
    listOptionTemplates: () => Promise.resolve([]),
    listPxeProfiles: () => Promise.resolve([]),
    updateScope: vi.fn(),
    // Edit reads the scope fresh on open (#3077).
    getScope: () =>
      Promise.resolve({
        id: "s1",
        subnet_id: "sub-a",
        group_id: "g-a",
        name: "x",
        options: [],
      }),
  },
  ipamApi: {
    getSubnet: () =>
      Promise.resolve({ id: "sub-a", network: "10.0.0.0/24", gateway: null }),
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

describe("Edit DHCP Scope group (#2479)", () => {
  it("shows the stored group read-only, with no group select", async () => {
    const scope = {
      id: "s1",
      subnet_id: "sub-a",
      group_id: "g-a",
      name: "x",
      options: [],
    } as unknown as DHCPScope;
    render(
      <QueryClientProvider client={new QueryClient()}>
        <CreateScopeModal scope={scope} onClose={() => {}} />
      </QueryClientProvider>,
    );
    await waitFor(() => expect(screen.getByText("group-a")).toBeTruthy());
    expect(screen.queryByText("group-b")).toBeNull();
    expect(screen.queryByText("— Pick a group —")).toBeNull();
  });
});
