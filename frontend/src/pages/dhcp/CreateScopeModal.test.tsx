/**
 * @vitest-environment jsdom
 *
 * The New DHCP Scope dialog's pre-fill (#1154).
 *
 * Two queries feed it: the platform DHCP defaults (`["settings"]`: DNS
 * servers, domain name, lease time) and the subnet (`["subnet", id]`:
 * Routers = its gateway, plus a suggested initial pool). The order they answer
 * in is not the dialog's to choose — the Dashboard has usually cached
 * `["settings"]` before anyone opens IPAM, while a hard reload fetches both
 * cold — so every test here fixes the order explicitly and checks what the
 * dialog SHOWS against what it SENDS. A scope saved with no Routers hands out
 * leases with no default gateway.
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

type SubnetFixture = {
  id: string;
  network: string;
  gateway: string | null;
  name: string;
};

const getSubnet = vi.fn<(id: string) => Promise<SubnetFixture>>();
const getSettings = vi.fn<() => Promise<unknown>>();
const createScope = vi.fn();
const createPool = vi.fn();

vi.mock("@/lib/api", () => ({
  dhcpApi: {
    listGroups: () => Promise.resolve([]),
    listOptionCodes: () => Promise.resolve([]),
    listOptionTemplates: () => Promise.resolve([]),
    listPxeProfiles: () => Promise.resolve([]),
    createScope: (...args: unknown[]) => createScope(...args),
    createPool: (...args: unknown[]) => createPool(...args),
  },
  ipamApi: {
    getSubnet: (id: string) => getSubnet(id),
    listSubnets: () => Promise.resolve([SUBNET_A, SUBNET_B]),
    getEffectiveSubnetDhcp: () =>
      Promise.resolve({
        dhcp_server_group_id: null,
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

const SUBNET_A: SubnetFixture = {
  id: "sub-a",
  network: "10.78.21.0/24",
  gateway: "10.78.21.1",
  name: "staff",
};
const SUBNET_B: SubnetFixture = {
  id: "sub-b",
  network: "10.78.22.0/24",
  gateway: "10.78.22.1",
  name: "guests",
};
const SUBNET_V6: SubnetFixture = {
  id: "sub-v6",
  network: "2001:db8:21::/64",
  gateway: "2001:db8:21::1",
  name: "staff-v6",
};
const SETTINGS = {
  dhcp_default_dns_servers: ["10.0.0.53"],
  dhcp_default_domain_name: "corp.example.test",
  dhcp_default_lease_time: 3600,
};

const { CreateScopeModal } = await import("./CreateScopeModal");

function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

function client(): QueryClient {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

function open(qc: QueryClient, subnetId?: string) {
  render(
    <QueryClientProvider client={qc}>
      <CreateScopeModal subnetId={subnetId} onClose={() => {}} />
    </QueryClientProvider>,
  );
}

/** The control a `<Field label>` wraps (the label has no `htmlFor`). */
function control(label: string): HTMLInputElement {
  return screen.getByText(label, { selector: "label" })
    .nextElementSibling as HTMLInputElement;
}

async function save() {
  fireEvent.change(control("Name"), { target: { value: "staff-scope" } });
  fireEvent.submit(control("Name").form!);
  await waitFor(() => expect(createScope).toHaveBeenCalledTimes(1));
  return createScope.mock.calls[0][1] as { options: unknown[] };
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("CreateScopeModal pre-fill (#1154)", () => {
  it("fills Routers and the pool when the subnet answers after cached settings", async () => {
    // The ordinary path: the Dashboard already loaded ["settings"], so it is
    // served from cache at once while the subnet GET is still in flight.
    const qc = client();
    qc.setQueryData(["settings"], SETTINGS);
    getSettings.mockResolvedValue(SETTINGS);
    const subnet = deferred<SubnetFixture>();
    getSubnet.mockReturnValue(subnet.promise);
    createScope.mockResolvedValue({ id: "scope-1" });
    createPool.mockResolvedValue({});

    open(qc, SUBNET_A.id);
    await waitFor(() =>
      expect(control("Domain Name (option 15)").value).toBe(
        "corp.example.test",
      ),
    );
    expect(control("Routers (option 3)").value).toBe("");

    await act(async () => subnet.resolve(SUBNET_A));
    await waitFor(() =>
      expect(control("Routers (option 3)").value).toBe("10.78.21.1"),
    );
    expect(control("Start IP").value).toBe("10.78.21.10");
    expect(control("End IP").value).toBe("10.78.21.254");

    const body = await save();
    expect(body.options).toContainEqual({
      code: 3,
      name: "routers",
      value: ["10.78.21.1"],
    });
    expect(body.options).toContainEqual({
      code: 15,
      name: "domain-name",
      value: "corp.example.test",
    });
    await waitFor(() =>
      expect(createPool).toHaveBeenCalledWith(
        "scope-1",
        expect.objectContaining({
          start_ip: "10.78.21.10",
          end_ip: "10.78.21.254",
        }),
      ),
    );
  });

  it("keeps the platform defaults when the subnet answers first", async () => {
    // A hard reload: nothing cached, and the subnet wins the race.
    const qc = client();
    const settings = deferred<unknown>();
    getSettings.mockReturnValue(settings.promise);
    getSubnet.mockResolvedValue(SUBNET_A);
    createScope.mockResolvedValue({ id: "scope-1" });
    createPool.mockResolvedValue({});

    open(qc, SUBNET_A.id);
    await waitFor(() =>
      expect(control("Routers (option 3)").value).toBe("10.78.21.1"),
    );
    expect(control("Domain Name (option 15)").value).toBe("");

    await act(async () => settings.resolve(SETTINGS));
    await waitFor(() =>
      expect(control("Domain Name (option 15)").value).toBe(
        "corp.example.test",
      ),
    );
    expect(control("DNS Servers (option 6)").value).toBe("10.0.0.53");
    expect(control("Routers (option 3)").value).toBe("10.78.21.1");

    const body = await save();
    expect(body.options).toContainEqual({
      code: 3,
      name: "routers",
      value: ["10.78.21.1"],
    });
    expect(body.options).toContainEqual({
      code: 6,
      name: "dns-servers",
      value: ["10.0.0.53"],
    });
    expect(createScope.mock.calls[0][1]).toMatchObject({ lease_time: 3600 });
  });

  it("never overwrites Routers the operator typed before the subnet answered", async () => {
    const qc = client();
    qc.setQueryData(["settings"], SETTINGS);
    getSettings.mockResolvedValue(SETTINGS);
    const subnet = deferred<SubnetFixture>();
    getSubnet.mockReturnValue(subnet.promise);
    createScope.mockResolvedValue({ id: "scope-1" });
    createPool.mockResolvedValue({});

    open(qc, SUBNET_A.id);
    await waitFor(() =>
      expect(control("Domain Name (option 15)").value).toBe(
        "corp.example.test",
      ),
    );
    const routers = control("Routers (option 3)");
    fireEvent.change(routers, { target: { value: "10.78.21.254" } });
    fireEvent.blur(routers);

    await act(async () => subnet.resolve(SUBNET_A));
    await waitFor(() => expect(control("Start IP").value).toBe("10.78.21.10"));
    expect(control("Routers (option 3)").value).toBe("10.78.21.254");

    const body = await save();
    expect(body.options).toContainEqual({
      code: 3,
      name: "routers",
      value: ["10.78.21.254"],
    });
  });

  it("follows a subnet picked in the dialog, but never over the operator's edit", async () => {
    // Opened from the DHCP page: no pinned subnet, a picker instead.
    const qc = client();
    qc.setQueryData(["settings"], SETTINGS);
    getSettings.mockResolvedValue(SETTINGS);
    getSubnet.mockImplementation((id) =>
      Promise.resolve(id === SUBNET_A.id ? SUBNET_A : SUBNET_B),
    );

    open(qc);
    const picker = await waitFor(() => {
      const select = control("Subnet (IPAM)") as unknown as HTMLSelectElement;
      expect(select.options.length).toBe(3);
      return select;
    });

    fireEvent.change(picker, { target: { value: SUBNET_A.id } });
    await waitFor(() =>
      expect(control("Routers (option 3)").value).toBe("10.78.21.1"),
    );
    expect(control("Start IP").value).toBe("10.78.21.10");

    // A different subnet replaces what the dialog filled in itself…
    fireEvent.change(picker, { target: { value: SUBNET_B.id } });
    await waitFor(() =>
      expect(control("Routers (option 3)").value).toBe("10.78.22.1"),
    );
    expect(control("Start IP").value).toBe("10.78.22.10");
    expect(control("End IP").value).toBe("10.78.22.254");

    // …but not what the operator changed.
    const routers = control("Routers (option 3)");
    fireEvent.change(routers, { target: { value: "10.78.22.254" } });
    fireEvent.blur(routers);
    fireEvent.change(control("Start IP"), {
      target: { value: "10.78.22.100" },
    });
    fireEvent.change(picker, { target: { value: SUBNET_A.id } });
    await waitFor(() =>
      expect(getSubnet).toHaveBeenLastCalledWith(SUBNET_A.id),
    );
    await act(async () => {});
    expect(control("Routers (option 3)").value).toBe("10.78.22.254");
    expect(control("Start IP").value).toBe("10.78.22.100");
  });

  it("does not put a DHCPv4 Routers option on an IPv6 scope", async () => {
    const qc = client();
    getSettings.mockResolvedValue(SETTINGS);
    getSubnet.mockResolvedValue(SUBNET_V6);

    open(qc, SUBNET_V6.id);
    await waitFor(() =>
      expect(control("DNS Servers (option 6)").value).toBe("10.0.0.53"),
    );
    await act(async () => {});
    expect(control("Routers (option 3)").value).toBe("");
  });
});
