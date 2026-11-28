/**
 * @vitest-environment jsdom
 *
 * vSphere page (#4740): a read-only account sees no write actions, the
 * Discovery view says why a VM has no address, and moving the vCenter address
 * asks for the stored password again.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const h = vi.hoisted(() => ({ superadmin: true }));

const ROW = {
  id: "t1",
  name: "vc-lab",
  description: "",
  enabled: true,
  host: "vc.example.test",
  port: 443,
  verify_tls: true,
  ca_bundle_present: false,
  username: "svc@vsphere.local",
  password_present: true,
  ipam_space_id: "sp1",
  mirror_vms: true,
  mirror_hosts: true,
  sync_interval_seconds: 120,
  last_synced_at: "2026-11-27T10:00:00Z",
  last_sync_error: null,
  vcenter_version: "8.0.2",
  host_count: 2,
  vm_count: 4,
  last_discovery: {
    summary: {
      vm_total: 4,
      vm_reporting: 1,
      vm_tools_not_running: 1,
      vm_powered_off: 1,
      vm_unreadable: 0,
      vm_no_ip: 0,
      host_total: 2,
      host_with_ip_name: 1,
      addresses_skipped_no_subnet: 1,
    },
    vms: [
      {
        vm: "vm-102",
        name: "db01",
        power_state: "POWERED_ON",
        guest_state: "tools_not_running",
        nic_count: 0,
        ips: [],
        issue: "tools_not_running",
        hint: "VMware Tools is not running in the guest",
      },
      {
        vm: "vm-101",
        name: "web01",
        power_state: "POWERED_ON",
        guest_state: "reporting",
        nic_count: 1,
        ips: ["10.20.1.10"],
        issue: null,
        hint: null,
      },
    ],
    generated_at: "2026-11-27T10:00:00Z",
  },
  created_at: "2026-11-27T09:00:00Z",
  modified_at: "2026-11-27T09:00:00Z",
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: async () => ({
        is_superadmin: h.superadmin,
        grants: [],
      }),
    },
    ipamApi: {
      ...actual.ipamApi,
      listSpaces: () => Promise.resolve([{ id: "sp1", name: "space one" }]),
    },
    vsphereApi: {
      ...actual.vsphereApi,
      listTargets: () => Promise.resolve([ROW]),
    },
  };
});

const { VspherePage } = await import("./VspherePage");

afterEach(() => {
  cleanup();
  h.superadmin = true;
});

function open() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <VspherePage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("VspherePage", () => {
  it("lists the vCenter with its counts and version", async () => {
    open();
    await screen.findByText("vc-lab");
    expect(screen.getByText("vc.example.test:443")).toBeTruthy();
    expect(screen.getByText("v8.0.2")).toBeTruthy();
    expect(screen.getByText("2 / 4")).toBeTruthy();
    expect(screen.getByText("1 vCenter configured")).toBeTruthy();
  });

  it("offers no write action to a read-only account", async () => {
    h.superadmin = false;
    open();
    await screen.findByText("vc-lab");
    for (const name of ["Edit", "Delete", "Sync Now"]) {
      const b = screen.getByRole("button", { name }) as HTMLButtonElement;
      expect(b.disabled).toBe(true);
    }
  });

  it("Discovery says a VM without VMware Tools is unknown, not empty", async () => {
    open();
    fireEvent.click(await screen.findByRole("button", { name: "Discovery" }));
    const dialog = await screen.findByText(/Discovery — vc-lab/);
    expect(dialog).toBeTruthy();
    expect(screen.getAllByText(/VMware Tools is not running/).length).toBe(2);
    const row = screen.getByText("db01").closest("tr") as HTMLElement;
    expect(within(row).getByText("tools_not_running")).toBeTruthy();
    expect(screen.getByText("10.20.1.10")).toBeTruthy();
  });

  it("asks for the stored password again when the address moves", async () => {
    open();
    fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
    const host = await screen.findByDisplayValue("vc.example.test");
    expect(screen.getByPlaceholderText(/stored/)).toBeTruthy();
    fireEvent.change(host, { target: { value: "vc2.example.test" } });
    expect(
      screen.getByPlaceholderText(/re-enter for the new address/),
    ).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "Save" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
  });
});
