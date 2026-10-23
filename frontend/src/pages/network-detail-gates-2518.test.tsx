/**
 * @vitest-environment jsdom
 *
 * A network object's own page offers a write only to a user who may make it
 * (#2518).
 *
 * #1851 gated the registries' list pages; the device, ASN, overlay and VRF
 * pages, and the device list's Active switch, still offered a read-only
 * Viewer every write, which the API then refused. Real `usePermissions`,
 * answered from `GET /auth/me/permissions`.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import type { ReactNode } from "react";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const stubs = Object.fromEntries(
    Object.entries(actual)
      .filter(([name, v]) => name.endsWith("Api") && typeof v === "object")
      .map(([name]) => [
        name,
        new Proxy(
          {},
          {
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : (...args: unknown[]) =>
                    (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const STAMP = "2026-10-22T00:00:00Z";
const VIEWER: [string, string][] = [["read", "*"]];
type Grants = [string, string][] | "superadmin";

function signInAs(grants: Grants) {
  answers.authApi = {
    myPermissions: () =>
      Promise.resolve(
        grants === "superadmin"
          ? { is_superadmin: true, grants: [] }
          : {
              is_superadmin: false,
              grants: grants.map(([action, resource_type]) => ({
                action,
                resource_type,
                resource_id: null,
              })),
            },
      ),
  };
}

async function show(ui: ReactNode, path: string, route: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path={route} element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Let the permission answer land: every gate is closed while it loads. */
async function settled() {
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
}

function expectDenied(el: HTMLElement, reason: string) {
  const b = el as HTMLButtonElement;
  expect(b.disabled, `${b.title || b.textContent} is offered`).toBe(true);
  expect(b.title).toBe(reason);
}
function expectOffered(el: HTMLElement) {
  expect((el as HTMLButtonElement).disabled).toBe(false);
}
const byName = (n: string | RegExp) => screen.getByRole("button", { name: n });

/** A gated icon button is named by its tooltip, so while it is denied the
 *  reason is its name. Every button carrying that reason is disabled; an
 *  enabled icon button is found by its own title instead. */
function expectIconsDenied(reason: string, count: number) {
  const found = screen.getAllByTitle(reason) as HTMLButtonElement[];
  expect(found.length).toBe(count);
  for (const b of found) expect(b.disabled).toBe(true);
}

// ── device ────────────────────────────────────────────────────────────────

const DEVICE = {
  id: "dev-1",
  name: "sw-viewer",
  hostname: "sw-viewer.test",
  ip_address: "192.0.2.10",
  device_type: "switch",
  description: null,
  vendor: null,
  sys_descr: null,
  sys_object_id: null,
  sys_name: null,
  sys_uptime_seconds: null,
  snmp_version: "v2c",
  snmp_port: 161,
  snmp_timeout_seconds: 5,
  snmp_retries: 1,
  has_community: true,
  v3_security_name: null,
  v3_security_level: null,
  v3_auth_protocol: null,
  has_auth_key: false,
  v3_priv_protocol: null,
  has_priv_key: false,
  v3_context_name: null,
  poll_interval_seconds: 300,
  poll_arp: true,
  poll_fdb: true,
  poll_interfaces: true,
  poll_lldp: true,
  auto_create_discovered: false,
  last_poll_at: null,
  next_poll_at: null,
  last_poll_status: "pending",
  last_poll_error: null,
  last_poll_arp_count: null,
  last_poll_fdb_count: null,
  last_poll_interface_count: null,
  last_poll_neighbour_count: null,
  ip_space_id: "sp-1",
  ip_space_name: "default",
  is_active: false,
  tags: {},
  created_at: STAMP,
  updated_at: STAMP,
};

describe("a device (#2518)", () => {
  async function openDetail(g: Grants, poll?: Answer) {
    signInAs(g);
    answers.networkApi = {
      getDevice: () => Promise.resolve(DEVICE),
      ...(poll ? { pollNow: poll } : {}),
    };
    const { DeviceDetailView } = await import("./network/DeviceDetailView");
    await show(
      <DeviceDetailView />,
      "/network/devices/dev-1",
      "/network/devices/:id",
    );
    await screen.findByText("sw-viewer");
    await settled();
  }

  it("offers a Viewer no Test Connection, Poll Now, Edit or Delete", async () => {
    await openDetail(VIEWER);
    const write = "Requires write permission on network devices";
    for (const n of [/Test Connection/, /Poll Now/, /^Edit$/])
      expectDenied(byName(n), write);
    expectDenied(
      byName(/^Delete$/),
      "Requires delete permission on network devices",
    );
  });

  it("offers a superadmin all four", async () => {
    await openDetail("superadmin");
    for (const n of [/Test Connection/, /Poll Now/, /^Edit$/, /^Delete$/])
      expectOffered(byName(n));
  });

  it("says a refused Poll Now was refused", async () => {
    const refusal = Object.assign(new Error("403"), {
      isAxiosError: true,
      response: { status: 403, data: { detail: "Permission denied" } },
    });
    await openDetail("superadmin", () => Promise.reject(refusal));
    fireEvent.click(byName(/Poll Now/));
    expect((await screen.findByRole("alert")).textContent).toMatch(
      /Permission denied/,
    );
  });

  it("gates the device list's Active switch", async () => {
    signInAs(VIEWER);
    answers.networkApi = {
      listDevices: () =>
        Promise.resolve({ items: [DEVICE], total: 1, page: 1, page_size: 50 }),
    };
    const { NetworkPage } = await import("./network/NetworkPage");
    await show(<NetworkPage />, "/network", "/network");
    await screen.findByText("sw-viewer");
    await settled();
    const sw = screen.getByLabelText("Active sw-viewer") as HTMLInputElement;
    expect(sw.disabled).toBe(true);
    expect(sw.title).toBe("Requires write permission on network devices");
    cleanup();
    signInAs("superadmin");
    await show(<NetworkPage />, "/network", "/network");
    await screen.findByText("sw-viewer");
    await settled();
    expect(
      (screen.getByLabelText("Active sw-viewer") as HTMLInputElement).disabled,
    ).toBe(false);
  });
});

// ── ASN ───────────────────────────────────────────────────────────────────

const PEERING = {
  id: "pe-1",
  local_asn_id: "asn-1",
  peer_asn_id: "asn-2",
  relationship_type: "peer",
  description: "",
  local_asn_number: 64512,
  local_asn_name: "us",
  peer_asn_number: 64513,
  peer_asn_name: "them",
  created_at: STAMP,
  modified_at: STAMP,
};

const COMMUNITY = {
  id: "co-1",
  asn_id: "asn-1",
  value: "64512:100",
  kind: "regular",
  name: "blackhole",
  description: "",
  inbound_action: "",
  outbound_action: "",
  tags: {},
  created_at: STAMP,
  modified_at: STAMP,
};

describe("an ASN's tabs (#2518)", () => {
  const WRITE = "Requires write permission on ASNs";
  const DELETE = "Requires delete permission on ASNs";

  it("offers a Viewer no peering write", async () => {
    signInAs(VIEWER);
    answers.asnsApi = { listPeerings: () => Promise.resolve([PEERING]) };
    const { PeeringsTab } = await import("./network/PeeringsTab");
    await show(<PeeringsTab asnId="asn-1" />, "/", "/");
    await screen.findByText(/AS64513/);
    await settled();
    expectIconsDenied(WRITE, 2); // Add Peering + the row's Edit
    expectIconsDenied(DELETE, 1);
    expect(screen.queryByRole("button", { name: "Edit" })).toBeNull();
  });

  it("offers a Viewer no community write", async () => {
    signInAs(VIEWER);
    answers.asnsApi = {
      listCommunities: () => Promise.resolve([COMMUNITY]),
      listStandardCommunities: () => Promise.resolve([]),
    };
    const { CommunitiesTab } = await import("./network/CommunitiesTab");
    await show(<CommunitiesTab asnId="asn-1" />, "/", "/");
    await screen.findByText("64512:100");
    await settled();
    expectIconsDenied(WRITE, 2); // Add Community + the row's Edit
    expectIconsDenied(DELETE, 1);
    expect(screen.queryByRole("button", { name: "Edit" })).toBeNull();
  });

  it("offers an ASN manager every one", async () => {
    signInAs([
      ["read", "*"],
      ["admin", "manage_asns"],
    ]);
    answers.asnsApi = {
      listPeerings: () => Promise.resolve([PEERING]),
    };
    const { PeeringsTab } = await import("./network/PeeringsTab");
    await show(<PeeringsTab asnId="asn-1" />, "/", "/");
    await screen.findByText(/AS64513/);
    await settled();
    for (const n of [/Add Peering/, "Edit", "Delete"]) expectOffered(byName(n));
  });
});

// ── overlay ───────────────────────────────────────────────────────────────

const OVERLAY = {
  id: "ov-1",
  name: "wan-viewer",
  kind: "sdwan",
  customer_id: null,
  vendor: null,
  encryption_profile: null,
  default_path_strategy: "preferred",
  status: "active",
  notes: "",
  tags: {},
  custom_fields: {},
  created_at: STAMP,
  modified_at: STAMP,
  site_count: 1,
  policy_count: 1,
};

const OV_SITE = {
  id: "os-1",
  overlay_network_id: "ov-1",
  site_id: "site-1",
  role: "spoke",
  device_id: null,
  loopback_subnet_id: null,
  preferred_circuits: [],
  notes: "",
  created_at: STAMP,
  modified_at: STAMP,
};

const OV_POLICY = {
  id: "op-1",
  overlay_network_id: "ov-1",
  name: "voice-first",
  priority: 10,
  match_kind: "application",
  match_value: "voice",
  action: "drop",
  action_target: null,
  enabled: true,
  notes: "",
  created_at: STAMP,
  modified_at: STAMP,
};

describe("an overlay's tabs (#2518)", () => {
  const WRITE = "Requires write permission on overlay networks";
  const DELETE = "Requires delete permission on overlay networks";

  async function openOverlay(g: Grants, tab: RegExp) {
    signInAs(g);
    answers.overlaysApi = {
      get: () => Promise.resolve(OVERLAY),
      listSites: () => Promise.resolve([OV_SITE]),
      listPolicies: () => Promise.resolve([OV_POLICY]),
    };
    answers.sitesApi = {
      list: () =>
        Promise.resolve({
          items: [{ id: "site-1", name: "hq", code: "HQ" }],
          total: 1,
        }),
    };
    const { OverlayDetailPage } = await import("./network/OverlayDetailPage");
    await show(
      <OverlayDetailPage />,
      "/network/overlays/ov-1",
      "/network/overlays/:id",
    );
    await screen.findByText("wan-viewer");
    fireEvent.click(byName(tab));
    await settled();
  }

  it("offers a Viewer no site write", async () => {
    await openOverlay(VIEWER, /^Sites/);
    expectIconsDenied(WRITE, 2); // Attach site + the row's Edit
    expectIconsDenied(DELETE, 1); // Detach
    expect(screen.queryByRole("button", { name: "Edit" })).toBeNull();
  });

  it("offers a Viewer no policy write", async () => {
    await openOverlay(VIEWER, /^Policies/);
    await screen.findByText("voice-first");
    // New policy + Move up + Move down + Edit
    expectIconsDenied(WRITE, 4);
    expectIconsDenied(DELETE, 1);
    expect(screen.queryByRole("button", { name: "Edit" })).toBeNull();
  });

  it("offers a superadmin the site and policy writes", async () => {
    await openOverlay("superadmin", /^Sites/);
    for (const n of [/Attach site/, "Edit", "Detach"]) expectOffered(byName(n));
    cleanup();
    await openOverlay("superadmin", /^Policies/);
    await screen.findByText("voice-first");
    for (const n of [/New policy/, "Edit", "Delete"]) expectOffered(byName(n));
  });
});

// ── VRF ───────────────────────────────────────────────────────────────────

const VRF = {
  id: "vrf-1",
  name: "vrf-viewer",
  description: "",
  asn_id: null,
  route_distinguisher: null,
  import_targets: [],
  export_targets: [],
  tags: {},
  custom_fields: {},
  customer_id: null,
  created_at: STAMP,
  modified_at: STAMP,
  space_count: 0,
  block_count: 0,
};

describe("a VRF (#2518)", () => {
  async function openVrf(g: Grants) {
    signInAs(g);
    answers.vrfsApi = { get: () => Promise.resolve(VRF) };
    const { VRFDetailPage } = await import("./vrfs/VRFDetailPage");
    await show(<VRFDetailPage />, "/vrfs/vrf-1", "/vrfs/:id");
    await screen.findByText("vrf-viewer");
    await settled();
  }

  it("offers a Viewer no Edit, and a VRF writer Edit", async () => {
    await openVrf(VIEWER);
    expectDenied(byName(/^Edit$/), "Requires write permission on VRFs");
    cleanup();
    await openVrf([
      ["read", "*"],
      ["write", "vrf"],
    ]);
    expectOffered(byName(/^Edit$/));
  });
});
