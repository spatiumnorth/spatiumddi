/**
 * @vitest-environment jsdom
 *
 * An integration's Edit dialog reads the row when it opens and a Save sends
 * only what the operator changed (#4370). Before, each dialog seeded its form
 * once from the click-time list row and sent every plain field back, so a
 * description, switch, IPAM space or enabled flag another client stored since
 * the list loaded was put back by an unrelated Save.
 *
 * Each case: the list first answers with the stale row (description "old
 * description"), then, once Edit is clicked and the list is read again, with
 * what another client stored since (description "changed elsewhere", enabled
 * flipped, another IPAM space). The operator changes only the sync interval.
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
import { MemoryRouter } from "react-router-dom";

const h = vi.hoisted(() => ({
  reads: 0,
  rows: [] as Record<string, unknown>[],
  update: vi.fn(),
  fail: false,
}));

function list() {
  const i = Math.min(h.reads, h.rows.length - 1);
  h.reads += 1;
  if (h.fail && h.reads > 1) return Promise.reject(new Error("boom"));
  return Promise.resolve([h.rows[i]]);
}
const upd = (...a: unknown[]) => {
  h.update(...a);
  return Promise.resolve(h.rows[h.rows.length - 1]);
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: async () => ({ is_superadmin: true, grants: [] }),
    },
    ipamApi: {
      ...actual.ipamApi,
      listSpaces: () =>
        Promise.resolve([
          { id: "sp1", name: "space one" },
          { id: "sp2", name: "space two" },
        ]),
    },
    dnsApi: { ...actual.dnsApi, listGroups: () => Promise.resolve([]) },
    proxmoxApi: { ...actual.proxmoxApi, listNodes: list, updateNode: upd },
    dockerApi: { ...actual.dockerApi, listHosts: list, updateHost: upd },
    kubernetesApi: {
      ...actual.kubernetesApi,
      listClusters: list,
      updateCluster: upd,
    },
    merakiApi: { ...actual.merakiApi, list, update: upd },
    unifiApi: {
      ...actual.unifiApi,
      listControllers: list,
      updateController: upd,
    },
    fortinetApi: { ...actual.fortinetApi, list, update: upd },
    panosApi: { ...actual.panosApi, list, update: upd },
    opnsenseApi: {
      ...actual.opnsenseApi,
      listRouters: list,
      updateRouter: upd,
    },
    netbirdApi: {
      ...actual.netbirdApi,
      listInstances: list,
      updateInstance: upd,
    },
    tailscaleApi: {
      ...actual.tailscaleApi,
      listTenants: list,
      updateTenant: upd,
    },
    cloudApi: { ...actual.cloudApi, listEndpoints: list, updateEndpoint: upd },
  };
});

const { ProxmoxPage } = await import("./proxmox/ProxmoxPage");
const { DockerPage } = await import("./docker/DockerPage");
const { KubernetesPage } = await import("./kubernetes/KubernetesPage");
const { MerakiPage } = await import("./meraki/MerakiPage");
const { UnifiPage } = await import("./unifi/UnifiPage");
const { FortinetPage } = await import("./fortinet/FortinetPage");
const { PanosPage } = await import("./panos/PanosPage");
const { OpnsensePage } = await import("./opnsense/OpnsensePage");
const { NetbirdPage } = await import("./netbird/NetbirdPage");
const { TailscalePage } = await import("./tailscale/TailscalePage");
const { CloudPage } = await import("./cloud/CloudPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  h.reads = 0;
  h.fail = false;
});

// A superset of every integration's fields: each form reads its own.
const BASE = {
  id: "r1",
  name: "lab",
  description: "old description",
  enabled: false,
  ipam_space_id: "sp1",
  dns_group_id: null,
  sync_interval_seconds: 600,
  host: "192.0.2.40",
  port: 8006,
  verify_tls: true,
  token_id: "tok@pve!x",
  token_secret_present: true,
  connection_type: "tcp",
  endpoint: "tcp://192.0.2.41:2376",
  client_key_present: true,
  api_server_url: "https://192.0.2.42:6443",
  token_present: true,
  base_url: "https://api.meraki.com/api/v1",
  org_id: "123",
  network_ids: [],
  api_key_present: true,
  mode: "local",
  auth_kind: "api_key",
  site_allowlist: [],
  vdom: "root",
  api_token_present: true,
  api_version: "11.1",
  is_panorama: false,
  vsys: "vsys1",
  device_group: "",
  api_key: "key",
  api_secret_present: true,
  api_url: "https://192.0.2.43",
  network_cidr: "100.64.0.0/10",
  cgnat_cidr: "100.64.0.0/10",
  ipv6_cidr: "fd7a:115c:a1e0::/48",
  tailnet: "example.com",
  provider: "aws",
  provider_config: {},
  regions: [],
  pod_cidr: "",
  service_cidr: "",
  last_sync_at: null,
  last_sync_error: null,
  mirror_vms: true,
  mirror_lxc: true,
  include_stopped: false,
  infer_vnet_subnets: false,
  mirror_containers: false,
  include_default_networks: false,
  include_stopped_containers: false,
  mirror_pods: false,
  skip_expired: true,
  mirror_policy_objects: true,
  mirror_vlans: true,
  mirror_dhcp_reservations: true,
  mirror_nat_rules: true,
  mirror_clients: true,
  mirror_networks: true,
  mirror_fixed_ips: true,
  include_wired: true,
  include_wireless: true,
  include_vpn: false,
  mirror_address_objects: true,
  mirror_interfaces: true,
  mirror_dhcp_leases: true,
  mirror_static_mappings: true,
  mirror_arp: false,
  mirror_load_balancers: false,
  mirror_stopped_instances: false,
  public_space_id: null,
};
const NEWER = {
  ...BASE,
  description: "changed elsewhere",
  enabled: true,
  ipam_space_id: "sp2",
  mirror_lxc: false,
};

const CASES: [string, () => React.ReactElement][] = [
  ["Proxmox", () => <ProxmoxPage />],
  ["Docker", () => <DockerPage />],
  ["Kubernetes", () => <KubernetesPage />],
  ["Meraki", () => <MerakiPage />],
  ["UniFi", () => <UnifiPage />],
  ["FortiGate", () => <FortinetPage />],
  ["PAN-OS", () => <PanosPage />],
  ["OPNsense", () => <OpnsensePage />],
  ["NetBird", () => <NetbirdPage />],
  ["Tailscale", () => <TailscalePage />],
  ["Cloud", () => <CloudPage />],
];

function open(page: () => React.ReactElement) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{page()}</MemoryRouter>
    </QueryClientProvider>,
  );
}

describe.each(CASES)("%s Edit dialog (#4370)", (_name, page) => {
  it("opens on what is stored now and a Save sends only what was changed", async () => {
    h.rows = [BASE, NEWER];
    open(page);
    fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
    // The dialog shows what the other client stored, not the click-time row.
    await screen.findByDisplayValue("changed elsewhere", {}, { timeout: 5000 });
    expect(screen.queryByDisplayValue("old description")).toBeNull();
    fireEvent.change(screen.getByDisplayValue("600"), {
      target: { value: "660" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(h.update).toHaveBeenCalledTimes(1), {
      timeout: 5000,
    });
    expect(h.update).toHaveBeenCalledWith("r1", { sync_interval_seconds: 660 });
  });

  it("a changed description is sent, and nothing else", async () => {
    h.rows = [NEWER];
    open(page);
    fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
    fireEvent.change(await screen.findByDisplayValue("changed elsewhere"), {
      target: { value: "mine" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(h.update).toHaveBeenCalledTimes(1), {
      timeout: 5000,
    });
    expect(h.update).toHaveBeenCalledWith("r1", { description: "mine" });
  });

  it("a failed read opens no form", async () => {
    h.rows = [BASE];
    h.fail = true;
    open(page);
    fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
    await screen.findByText(/Couldn't read the current values/);
    expect(screen.queryByRole("button", { name: "Save" })).toBeNull();
  });
});
