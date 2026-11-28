/**
 * @vitest-environment jsdom
 *
 * #4428: the Fleet drilldown's "Network interfaces" section. The behaviours
 * worth pinning are the ones an operator could be misled by: a change the
 * node rolled back must not read as applied, a port the node cannot manage
 * must not be offered, a refusal from the server must be shown in the dialog,
 * and an unreported node is unknown rather than "no interfaces".
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { NetworkInterfacesResponse } from "@/lib/api";

const get = vi.fn();
const put = vi.fn();
const del = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    applianceApi: {
      ...actual.applianceApi,
      getNetworkInterfaces: (...a: unknown[]) => get(...a),
      putNetworkInterfaces: (...a: unknown[]) => put(...a),
      deleteNetworkInterface: (...a: unknown[]) => del(...a),
    },
  };
});

let admin = true;
vi.mock("@/hooks/usePermissions", () => ({
  usePermissions: () => ({
    can: (action: string, resource: string) =>
      resource === "appliance" && (action === "read" || admin),
  }),
}));

const { ApplianceNetworkInterfacesSection } =
  await import("./NetworkInterfacesSection");
const { parseRoutes } = await import("./networkInterfaces");

function nic(over: Partial<NetworkInterfacesResponse["nics"][0]>) {
  return {
    name: "ens19",
    kind: "ethernet",
    parent: null,
    vlan_id: null,
    master: null,
    state: "up",
    carrier: true,
    mtu: 1500,
    mac: "52:54:00:aa:bb:cc",
    addresses: [],
    managed: false,
    protected_reason: null,
    ...over,
  };
}

function iface(over: Partial<NetworkInterfacesResponse["interfaces"][0]>) {
  return {
    name: "ens19",
    kind: "ethernet" as const,
    parent: null,
    vlan_id: null,
    addresses: ["10.9.0.2/24"],
    mtu: null,
    up: true,
    routes: [
      { destination: "172.16.5.0/24", gateway: "10.9.0.1", metric: null },
    ],
    description: null,
    state: "active" as const,
    detail: null,
    live_addresses: [],
    live_state: "up",
    live_carrier: true,
    ...over,
  };
}

function response(
  over: Partial<NetworkInterfacesResponse> = {},
): NetworkInterfacesResponse {
  return {
    reported: true,
    hostname: "ddi1",
    interfaces: [],
    nics: [
      nic({
        name: "ens18",
        addresses: ["192.168.1.10/24"],
        protected_reason:
          "it is the appliance's primary interface, owned by the installer",
      }),
      nic({ name: "ens19" }),
      nic({ name: "ens20" }),
    ],
    apply_state: null,
    apply_error: null,
    revert_seconds: 180,
    ...over,
  };
}

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ApplianceNetworkInterfacesSection applianceId="ap-1" />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  admin = true;
  get.mockReset();
  put.mockReset();
  del.mockReset();
});
afterEach(cleanup);

describe("parseRoutes", () => {
  it("reads 'dest via gw [metric n]' lines", () => {
    expect(
      parseRoutes(
        "10.20.0.0/16 via 10.9.0.1\n\n172.16.0.0/12 via 10.9.0.254 metric 50",
      ),
    ).toEqual([
      { destination: "10.20.0.0/16", gateway: "10.9.0.1", metric: null },
      { destination: "172.16.0.0/12", gateway: "10.9.0.254", metric: 50 },
    ]);
  });
  it("names the line it cannot read", () => {
    expect(() => parseRoutes("10.20.0.0/16 via 10.9.0.1\nnonsense")).toThrow(
      /Route line 2/,
    );
  });
});

describe("Network interfaces section", () => {
  it("lists configured interfaces with their state and routes", async () => {
    get.mockResolvedValue(
      response({
        interfaces: [
          iface({}),
          iface({
            name: "ens19.100",
            kind: "vlan",
            parent: "ens19",
            vlan_id: 100,
            addresses: ["10.10.0.2/24"],
            routes: [],
            state: "inactive",
            detail: "the link is down — no cable or no carrier",
          }),
        ],
      }),
    );
    mount();
    expect(await screen.findByText("Network interfaces")).toBeTruthy();
    expect(screen.getByText("VLAN 100 on ens19")).toBeTruthy();
    expect(screen.getByText("active")).toBeTruthy();
    expect(screen.getByText("inactive")).toBeTruthy();
    expect(screen.getByText(/no cable or no carrier/)).toBeTruthy();
    expect(screen.getByText("172.16.5.0/24 via 10.9.0.1")).toBeTruthy();
  });

  it("says plainly that a rolled-back change is not in force", async () => {
    get.mockResolvedValue(
      response({
        interfaces: [iface({ state: "reverted" })],
        apply_state: "reverted",
        apply_error: "The node could not reach the control plane.",
      }),
    );
    mount();
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/rolled back/);
    expect(alert.textContent).toMatch(/not what the node is running/);
  });

  it("warns while the node is confirming and names the window", async () => {
    get.mockResolvedValue(
      response({
        interfaces: [iface({ state: "confirming" })],
        apply_state: "pending-confirm",
      }),
    );
    mount();
    expect(await screen.findByText(/within 180 seconds/)).toBeTruthy();
  });

  it("treats an unreported node as unknown and offers no add button", async () => {
    get.mockResolvedValue(response({ reported: false, nics: [] }));
    mount();
    expect(
      await screen.findByText(/has not reported its network/),
    ).toBeTruthy();
    expect(screen.queryByText("Add interface…")).toBeNull();
  });

  it("hides every write control without admin on appliance", async () => {
    admin = false;
    get.mockResolvedValue(response({ interfaces: [iface({})] }));
    mount();
    await screen.findByText("Network interfaces");
    expect(screen.getAllByText("ens19").length).toBeGreaterThan(0);
    expect(screen.queryByText("Add interface…")).toBeNull();
    expect(screen.queryByText("Edit")).toBeNull();
    expect(screen.queryByText("Remove")).toBeNull();
  });

  it("shows why the primary interface cannot be managed", async () => {
    get.mockResolvedValue(response());
    mount();
    expect(await screen.findByText(/Not manageable here/)).toBeTruthy();
    expect(
      screen.getByText(/primary interface, owned by the installer/),
    ).toBeTruthy();
  });

  it("does not offer the protected port, and submits the whole set", async () => {
    get.mockResolvedValue(
      response({
        interfaces: [
          iface({ name: "ens20", addresses: ["10.8.0.2/24"], routes: [] }),
        ],
      }),
    );
    put.mockResolvedValue(response());
    mount();
    fireEvent.click(await screen.findByText("Add interface…"));

    const port = (await screen.findByLabelText("Port")) as HTMLSelectElement;
    const offered = within(port)
      .getAllByRole("option")
      .map((o) => o.textContent ?? "");
    // ens18 is the primary; ens20 is already managed; only ens19 is left.
    expect(offered.join(" ")).toMatch(/ens19/);
    expect(offered.join(" ")).not.toMatch(/ens18/);
    expect(offered.join(" ")).not.toMatch(/ens20/);

    fireEvent.change(screen.getByLabelText("Addresses"), {
      target: { value: "10.9.0.2/24" },
    });
    fireEvent.change(screen.getByLabelText(/Static routes/), {
      target: { value: "172.16.5.0/24 via 10.9.0.1 metric 20" },
    });
    fireEvent.change(screen.getByLabelText("MTU"), {
      target: { value: "1400" },
    });
    fireEvent.click(screen.getByText("Save"));

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1));
    const [id, body] = put.mock.calls[0];
    expect(id).toBe("ap-1");
    // The existing interface rides along: PUT replaces the whole set.
    expect(body.map((b: { name: string }) => b.name)).toEqual([
      "ens20",
      "ens19",
    ]);
    expect(body[1]).toMatchObject({
      kind: "ethernet",
      addresses: ["10.9.0.2/24"],
      mtu: 1400,
      up: true,
      routes: [
        { destination: "172.16.5.0/24", gateway: "10.9.0.1", metric: 20 },
      ],
    });
  });

  it("builds a VLAN with its parent and id", async () => {
    get.mockResolvedValue(response());
    put.mockResolvedValue(response());
    mount();
    fireEvent.click(await screen.findByText("Add interface…"));
    fireEvent.change(await screen.findByLabelText("Kind"), {
      target: { value: "vlan" },
    });
    fireEvent.change(screen.getByLabelText("VLAN ID"), {
      target: { value: "100" },
    });
    fireEvent.change(screen.getByLabelText("Addresses"), {
      target: { value: "10.10.0.2/24" },
    });
    fireEvent.click(screen.getByText("Save"));
    await waitFor(() => expect(put).toHaveBeenCalled());
    expect(put.mock.calls[0][1][0]).toMatchObject({
      kind: "vlan",
      parent: "ens18",
      vlan_id: 100,
      name: null,
    });
  });

  it("shows the server's refusal inside the dialog", async () => {
    get.mockResolvedValue(response());
    put.mockRejectedValue({
      isAxiosError: true,
      response: {
        status: 422,
        data: { detail: "ens19: 10.9.0.2/24 overlaps 192.168.1.0/24 on ens18" },
      },
    });
    mount();
    fireEvent.click(await screen.findByText("Add interface…"));
    fireEvent.change(await screen.findByLabelText("Addresses"), {
      target: { value: "10.9.0.2/24" },
    });
    fireEvent.click(screen.getByText("Save"));
    const alert = await screen.findByText(/overlaps 192.168.1.0\/24 on ens18/);
    expect(alert.getAttribute("role")).toBe("alert");
  });

  it("refuses a route line it cannot parse before calling the server", async () => {
    get.mockResolvedValue(response());
    mount();
    fireEvent.click(await screen.findByText("Add interface…"));
    fireEvent.change(await screen.findByLabelText(/Static routes/), {
      target: { value: "go left" },
    });
    fireEvent.click(screen.getByText("Save"));
    expect((await screen.findByRole("alert")).textContent).toMatch(
      /Route line 1/,
    );
    expect(put).not.toHaveBeenCalled();
  });

  it("removes an interface after confirmation", async () => {
    get.mockResolvedValue(response({ interfaces: [iface({})] }));
    del.mockResolvedValue(response());
    mount();
    fireEvent.click(await screen.findByText("Remove"));
    expect(await screen.findByText("Remove ens19?")).toBeTruthy();
    fireEvent.click(screen.getAllByText("Remove").slice(-1)[0]);
    await waitFor(() => expect(del).toHaveBeenCalledWith("ap-1", "ens19"));
  });
});
