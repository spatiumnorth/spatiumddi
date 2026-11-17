/**
 * @vitest-environment jsdom
 *
 * #3865 — New DHCP Scope reads the subnet's DHCP group (and gateway) fresh
 * every time it opens, selects the group that answer names, and says it is
 * reading — not that no group is set — while the read is on its way.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const getEffective = vi.fn();
const getSubnet = vi.fn();
const createScope = vi.fn();

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
    createScope: (...a: unknown[]) => createScope(...a),
    createPool: () => Promise.resolve({}),
  },
  ipamApi: {
    getSubnet: (id: string) => getSubnet(id),
    listSubnets: () => Promise.resolve([]),
    getEffectiveSubnetDhcp: () => getEffective(),
  },
  settingsApi: { get: () => Promise.resolve({}) },
}));
vi.mock("./windowsFailover", () => ({
  GROUP_FAILOVER_QUERY_KEY: "dhcp-group-failover",
  useGroupFailover: () => ({ data: undefined }),
}));

const { CreateScopeModal } = await import("./CreateScopeModal");

const eff = (id: string | null) => ({
  dhcp_server_group_id: id,
  inherited_from_block_id: null,
  inherited_from_space: false,
});
const subnet = (gateway: string) => ({
  id: "sub-a",
  network: "10.0.0.0/24",
  gateway,
  name: "n",
});

function open(qc: QueryClient) {
  render(
    <QueryClientProvider client={qc}>
      <CreateScopeModal subnetId="sub-a" onClose={() => {}} />
    </QueryClientProvider>,
  );
}
function control(label: string): HTMLInputElement {
  return screen.getByText(label, { selector: "label" })
    .nextElementSibling as HTMLInputElement;
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("New DHCP Scope reads the subnet fresh (#3865)", () => {
  it("selects and saves the group the subnet has now, not a cached one", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    // A previous open cached group A, still inside the 30 s staleTime.
    qc.setQueryData(["subnet-effective-dhcp", "sub-a"], eff("g-a"));
    qc.setQueryData(["subnet", "sub-a"], subnet("10.0.0.1"));
    getEffective.mockResolvedValue(eff("g-b"));
    getSubnet.mockResolvedValue(subnet("10.0.0.2"));
    createScope.mockResolvedValue({ id: "s1" });

    open(qc);
    await waitFor(() =>
      expect(control("Routers (option 3)").value).toBe("10.0.0.2"),
    );
    await waitFor(() => expect(control("DHCP Server Group").value).toBe("g-b"));
    fireEvent.change(control("Name"), { target: { value: "x" } });
    fireEvent.submit(control("Name").form!);
    await waitFor(() => expect(createScope).toHaveBeenCalledTimes(1));
    expect(createScope.mock.calls[0][1].group_id).toBe("g-b");
  });

  it("says it is reading, not that no group is set, while the read is pending", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    let resolve!: (v: unknown) => void;
    getEffective.mockReturnValue(new Promise((r) => (resolve = r)));
    getSubnet.mockResolvedValue(subnet("10.0.0.1"));

    open(qc);
    await screen.findByText("Reading this subnet's DHCP group…");
    expect(screen.queryByText(/No DHCP group set/)).toBeNull();

    await act(async () => resolve(eff("g-a")));
    await waitFor(() => expect(control("DHCP Server Group").value).toBe("g-a"));
    expect(screen.queryByText(/Reading this subnet/)).toBeNull();
  });
});
