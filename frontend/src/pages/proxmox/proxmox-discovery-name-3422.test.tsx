/**
 * @vitest-environment jsdom
 *
 * A Proxmox endpoint's Discovery button is named by its action, whatever
 * the sync state (#3422).
 *
 * The button holds only an icon, so without an aria-label its title is its
 * accessible name, and the title tells the sync state: until the endpoint
 * had synced once, a screen reader announced it as "Sync at least once to
 * populate discovery", an instruction rather than the control, and once it
 * had synced, as the whole tooltip. It is named "Discovery" in both states
 * now, and the state stays its title (the tooltip, and the accessible
 * description), the pattern the row's other icon buttons follow (#3402).
 */

import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ProxmoxDiscovery, ProxmoxNode } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
/** Per API object, the calls a test answers. Anything else stays pending. */
const answers = vi.hoisted(
  () => ({}) as Record<string, Record<string, Answer>>,
);

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

const { ProxmoxPage } = await import("./ProxmoxPage");

const NEVER_SYNCED: ProxmoxNode = {
  id: "00000000-0000-4000-8000-000000003422",
  name: "pve-new",
  description: "",
  enabled: true,
  host: "192.0.2.10",
  port: 8006,
  verify_tls: true,
  ca_bundle_present: false,
  token_id: "spatiumddi@pve!spatiumddi",
  token_secret_present: true,
  ipam_space_id: "00000000-0000-4000-8000-000000000001",
  dns_group_id: null,
  mirror_vms: true,
  mirror_lxc: true,
  include_stopped: false,
  infer_vnet_subnets: false,
  sync_interval_seconds: 60,
  last_synced_at: null,
  last_sync_error: null,
  pve_version: null,
  cluster_name: null,
  node_count: null,
  last_discovery: null,
  created_at: "2026-11-03T12:00:00Z",
  modified_at: "2026-11-03T12:00:00Z",
};

const DISCOVERY: ProxmoxDiscovery = {
  summary: {
    vm_total: 1,
    vm_agent_reporting: 1,
    vm_agent_not_responding: 0,
    vm_agent_off: 0,
    vm_no_nic: 0,
    lxc_total: 0,
    lxc_reporting: 0,
    lxc_no_ip: 0,
    sdn_vnets_total: 0,
    sdn_vnets_with_subnet: 0,
    sdn_vnets_unresolved: 0,
    addresses_skipped_no_subnet: 0,
    desired_subnets: 1,
  },
  guests: [
    {
      kind: "qemu",
      vmid: 101,
      name: "web-1",
      node: "pve1",
      status: "running",
      nic_count: 1,
      bridges: ["vmbr0"],
      ips_mirrored: 1,
      ips_from_agent: 1,
      ips_from_static: 0,
      agent_state: "reporting",
      issue: null,
      hint: null,
    },
  ],
  generated_at: "2026-11-03T12:05:00Z",
};

const SYNCED: ProxmoxNode = {
  ...NEVER_SYNCED,
  id: "00000000-0000-4000-8000-000000003423",
  name: "pve-lab",
  host: "192.0.2.11",
  last_synced_at: "2026-11-03T12:05:00Z",
  pve_version: "8.2.4",
  cluster_name: "lab",
  node_count: 3,
  last_discovery: DISCOVERY,
};

const NEVER_SYNCED_TIP = "Sync at least once to populate discovery";

function show() {
  answers.authApi = {
    myPermissions: async () => ({ is_superadmin: true, grants: [] }),
  };
  answers.proxmoxApi = { listNodes: async () => [NEVER_SYNCED, SYNCED] };
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/proxmox"]}>
        <ProxmoxPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** The table row of the endpoint named `name`, once the list has loaded. */
async function row(name: string): Promise<HTMLElement> {
  const cell = await screen.findByText(name, { exact: true });
  const tr = cell.closest("tr");
  expect(tr, `no table row holds ${name}`).not.toBeNull();
  return tr as HTMLElement;
}

afterEach(() => {
  cleanup();
  for (const k of Object.keys(answers)) delete answers[k];
});

describe("the Proxmox endpoint Discovery button (#3422)", () => {
  it("is named Discovery before the endpoint has synced, with the state kept as its tooltip", async () => {
    show();
    const tr = await row("pve-new");
    const discovery = within(tr).getByRole("button", {
      name: "Discovery",
      description: NEVER_SYNCED_TIP,
    }) as HTMLButtonElement;
    expect(discovery.title).toBe(NEVER_SYNCED_TIP);
    // Nothing to show until a sync has run.
    expect(discovery.disabled).toBe(true);
    expect(
      screen.queryByRole("button", { name: /sync at least once/i }),
    ).toBeNull();
  });

  it("is named Discovery once the endpoint has synced, and opens that endpoint's discovery", async () => {
    show();
    const tr = await row("pve-lab");
    const discovery = within(tr).getByRole("button", {
      name: "Discovery",
      description: /see which guests aren't reporting IPs/,
    }) as HTMLButtonElement;
    expect(discovery.disabled).toBe(false);
    fireEvent.click(discovery);
    const dialog = await screen.findByRole("dialog", { name: /pve-lab/ });
    // The endpoint's own report, not the "no discovery data yet" fallback.
    expect(within(dialog).getByText(/Snapshot from last sync/)).toBeTruthy();
  });

  it("has the same name on every row, whatever its sync state", async () => {
    show();
    await row("pve-new");
    await row("pve-lab");
    expect(screen.getAllByRole("button", { name: "Discovery" })).toHaveLength(
      2,
    );
  });
});
