/**
 * @vitest-environment jsdom
 *
 * #3867 — New DHCP Scope's suggested dynamic pool leaves the subnet's gateway
 * out, and the dialog shows the API's notice when a pool still holds IPAM
 * addresses.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const getSubnet = vi.fn();
const createScope = vi.fn();
const createPool = vi.fn();

vi.mock("@/lib/api", () => ({
  dhcpApi: {
    listGroups: () => Promise.resolve([]),
    listOptionCodes: () => Promise.resolve([]),
    listOptionTemplates: () => Promise.resolve([]),
    listPxeProfiles: () => Promise.resolve([]),
    createScope: (...a: unknown[]) => createScope(...a),
    createPool: (...a: unknown[]) => createPool(...a),
  },
  ipamApi: {
    getSubnet: (id: string) => getSubnet(id),
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

const subnet = (gateway: string | null) => ({
  id: "sub-a",
  network: "10.0.20.0/24",
  gateway,
  name: "n",
});

function open(onClose = () => {}) {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <CreateScopeModal subnetId="sub-a" onClose={onClose} />
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

describe("New DHCP Scope pool suggestion (#3867)", () => {
  it("stops below a gateway at the subnet's last host", async () => {
    getSubnet.mockResolvedValue(subnet("10.0.20.254"));
    open();
    await waitFor(() => expect(control("End IP").value).toBe("10.0.20.253"));
    expect(control("Start IP").value).toBe("10.0.20.10");
  });

  it("starts above a gateway at the pool's first address", async () => {
    getSubnet.mockResolvedValue(subnet("10.0.20.10"));
    open();
    await waitFor(() => expect(control("Start IP").value).toBe("10.0.20.11"));
    expect(control("End IP").value).toBe("10.0.20.254");
  });

  it("leaves the usual .1 gateway alone", async () => {
    getSubnet.mockResolvedValue(subnet("10.0.20.1"));
    open();
    await waitFor(() => expect(control("End IP").value).toBe("10.0.20.254"));
    expect(control("Start IP").value).toBe("10.0.20.10");
  });

  it("shows the API's notice about addresses in the pool instead of closing", async () => {
    getSubnet.mockResolvedValue(subnet("10.0.20.1"));
    createScope.mockResolvedValue({ id: "s1" });
    createPool.mockResolvedValue({
      existing_ips_in_range: [
        { address: "10.0.20.50", status: "reserved", hostname: "printer" },
      ],
    });
    const onClose = vi.fn();
    open(onClose);
    await waitFor(() => expect(control("End IP").value).toBe("10.0.20.254"));
    fireEvent.change(control("Name"), { target: { value: "x" } });
    fireEvent.submit(control("Name").form!);
    await screen.findByText(/existing IP/);
    expect(screen.getByText(/10\.0\.20\.50/)).toBeTruthy();
    expect(onClose).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText("OK"));
    expect(onClose).toHaveBeenCalled();
  });
});
