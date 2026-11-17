/**
 * @vitest-environment jsdom
 *
 * #4025 / #4026 — New DHCP Scope pre-fills the platform DHCP defaults for the
 * scope's address family, from the settings answer the dialog read itself.
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
const getSettings = vi.fn();
const createScope = vi.fn();

vi.mock("@/lib/api", () => ({
  dhcpApi: {
    listGroups: () =>
      Promise.resolve([{ id: "g", name: "grp", mode: "standalone" }]),
    listOptionCodes: () => Promise.resolve([]),
    listOptionTemplates: () =>
      Promise.resolve([
        { id: "t4", name: "tpl4", address_family: "ipv4", options: {} },
        { id: "t6", name: "tpl6", address_family: "ipv6", options: {} },
      ]),
    listPxeProfiles: () => Promise.resolve([]),
    createScope: (...a: unknown[]) => createScope(...a),
    createPool: () => Promise.resolve({}),
  },
  ipamApi: {
    getSubnet: (id: string) => getSubnet(id),
    listSubnets: () => Promise.resolve([]),
    getEffectiveSubnetDhcp: () =>
      Promise.resolve({
        dhcp_server_group_id: "g",
        inherited_from_block_id: null,
        inherited_from_space: false,
      }),
  },
  settingsApi: { get: () => getSettings() },
}));
vi.mock("./windowsFailover", () => ({
  GROUP_FAILOVER_QUERY_KEY: "dhcp-group-failover",
  useGroupFailover: () => ({ data: undefined }),
}));

const { CreateScopeModal } = await import("./CreateScopeModal");

const v6 = { id: "s", network: "fd00:1::/64", gateway: null, name: "n" };
const v4 = { id: "s", network: "10.0.0.0/24", gateway: "10.0.0.1", name: "n" };

function open(qc: QueryClient) {
  render(
    <QueryClientProvider client={qc}>
      <CreateScopeModal subnetId="s" onClose={() => {}} />
    </QueryClientProvider>,
  );
}
function dnsInput(): HTMLInputElement {
  return screen.getByText(/DNS Servers/, { selector: "label" })
    .nextElementSibling as HTMLInputElement;
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("platform defaults follow the scope's family (#4025)", () => {
  it("leaves IPv4-only defaults off an IPv6 scope", async () => {
    getSubnet.mockResolvedValue(v6);
    getSettings.mockResolvedValue({
      dhcp_default_dns_servers: ["192.0.2.53", "2001:db8::53"],
      dhcp_default_domain_name: "example.test",
      dhcp_default_ntp_servers: ["192.0.2.123"],
    });
    createScope.mockResolvedValue({ id: "x" });
    open(new QueryClient());
    await waitFor(() => expect(dnsInput().value).toContain("2001:db8::53"));
    expect(dnsInput().value).not.toContain("192.0.2.53");
    expect(screen.queryByDisplayValue("example.test")).toBeNull();
    const name = screen.getByText("Name", { selector: "label" })
      .nextElementSibling as HTMLInputElement;
    fireEvent.change(name, { target: { value: "x" } });
    fireEvent.submit(name.form!);
    await waitFor(() => expect(createScope).toHaveBeenCalled());
    const codes = createScope.mock.calls[0][1].options.map(
      (o: { code: number }) => o.code,
    );
    expect(codes).toEqual([6]);
  });

  it("offers only the templates of the scope's family", async () => {
    getSubnet.mockResolvedValue(v6);
    getSettings.mockResolvedValue({});
    open(new QueryClient());
    await screen.findByRole("option", { name: "tpl6 (v6)" });
    expect(screen.queryByRole("option", { name: "tpl4" })).toBeNull();
  });
});

describe("platform defaults come from the fresh read (#4026)", () => {
  it("replaces a cached default with the one the fresh read brings", async () => {
    getSubnet.mockResolvedValue(v4);
    getSettings.mockResolvedValue({ dhcp_default_dns_servers: ["192.0.2.54"] });
    const qc = new QueryClient();
    qc.setQueryData(["settings"], {
      dhcp_default_dns_servers: ["192.0.2.53"],
    });
    open(qc);
    await waitFor(() => expect(dnsInput().value).toContain("192.0.2.54"));
    expect(dnsInput().value).not.toContain("192.0.2.53");
  });
});
