/**
 * @vitest-environment jsdom
 *
 * The network device Edit dialog reads the device when it opens and a Save
 * sends only what the operator changed (#4370): a description, poll switch or
 * IP space another client stored since the list loaded is not put back.
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
import type { NetworkDeviceRead } from "@/lib/api";

const h = vi.hoisted(() => ({
  update: vi.fn(),
  get: vi.fn(),
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    networkApi: {
      ...actual.networkApi,
      getDevice: (...a: unknown[]) => h.get(...a),
      updateDevice: (...a: unknown[]) => {
        h.update(...a);
        return Promise.resolve({});
      },
    },
    ipamApi: {
      ...actual.ipamApi,
      listSpaces: () =>
        Promise.resolve([
          { id: "sp1", name: "space one" },
          { id: "sp2", name: "space two" },
        ]),
    },
  };
});

const { DeviceFormModal } = await import("./DeviceFormModal");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const OLD = {
  id: "d1",
  name: "sw1",
  hostname: "sw1",
  ip_address: "192.0.2.10",
  device_type: "switch",
  ip_space_id: "sp1",
  description: "old description",
  snmp_version: "v2c",
  snmp_port: 161,
  snmp_timeout_seconds: 5,
  snmp_retries: 1,
  has_community: true,
  has_auth_key: false,
  has_priv_key: false,
  v3_security_name: null,
  v3_security_level: null,
  v3_auth_protocol: null,
  v3_priv_protocol: null,
  v3_context_name: null,
  poll_interval_seconds: 300,
  poll_arp: true,
  poll_fdb: true,
  poll_interfaces: true,
  poll_lldp: true,
  auto_create_discovered: false,
  is_active: true,
} as unknown as NetworkDeviceRead;
const NEWER = {
  ...OLD,
  description: "changed elsewhere",
  ip_space_id: "sp2",
  poll_arp: false,
  is_active: false,
} as unknown as NetworkDeviceRead;

function open() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <DeviceFormModal device={OLD} onClose={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("network device Edit dialog (#4370)", () => {
  it("opens on what is stored now and a Save sends only what was changed", async () => {
    h.get.mockResolvedValue(NEWER);
    open();
    await screen.findByDisplayValue("changed elsewhere", {}, { timeout: 5000 });
    expect(screen.queryByDisplayValue("old description")).toBeNull();
    fireEvent.change(screen.getByDisplayValue("300"), {
      target: { value: "600" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(h.update).toHaveBeenCalledTimes(1), {
      timeout: 5000,
    });
    expect(h.update).toHaveBeenCalledWith("d1", {
      poll_interval_seconds: 600,
    });
  });

  it("a changed description is sent, and nothing else", async () => {
    h.get.mockResolvedValue(NEWER);
    open();
    fireEvent.change(await screen.findByDisplayValue("changed elsewhere"), {
      target: { value: "mine" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(h.update).toHaveBeenCalledTimes(1), {
      timeout: 5000,
    });
    expect(h.update).toHaveBeenCalledWith("d1", { description: "mine" });
  });

  it("a failed read opens no form", async () => {
    h.get.mockRejectedValue(new Error("boom"));
    open();
    await screen.findByText(/Couldn't read the current values/);
    expect(screen.queryByRole("button", { name: "Save" })).toBeNull();
  });
});
