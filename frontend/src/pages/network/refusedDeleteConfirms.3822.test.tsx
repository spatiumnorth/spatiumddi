/**
 * @vitest-environment jsdom
 *
 * A refused delete on the BACnet, AV, OT lists and the DNS blocking lists
 * keeps its confirm open and says why, in the server's words (#3822). Before,
 * the three registry pages left the confirm as it was with no word, and the
 * blocking lists' bulk delete read none of its results and closed as if every
 * delete had worked.
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

const DETAIL = "Thing is in use";
const listCalls: Record<string, number> = {};
const ts = "2026-01-01T00:00:00Z";

const FLOW = {
  id: "f1",
  group_id: "g1",
  av_protocol: "dante",
  av_flow_label: "flow",
  ptp_domain: null,
  seen_via: "manual",
  notes: "",
  custom_fields: {},
  created_at: ts,
  modified_at: ts,
  group_address: "239.1.1.1",
  group_name: "grp",
  group_application: "",
  space_id: "sp",
  vlan_id: null,
};
const RANGE = {
  id: "r1",
  space_id: "sp",
  cidr: "239.2.0.0/16",
  av_protocol: "dante",
  name: "rng",
  description: "",
  exclusive: false,
  vlan_id: null,
  tags: {},
  created_at: ts,
  modified_at: ts,
};
const BACNET = {
  id: "b1",
  ip_address_id: "ip",
  subnet_id: null,
  address: "10.0.0.1",
  hostname: null,
  device_instance: 42,
  vendor_id: null,
  vendor_name: "",
  vendor_label: null,
  device_name: "ahu-one",
  model_name: "",
  firmware_rev: "",
  location: "",
  max_apdu: null,
  segmentation_supported: null,
  network_number: null,
  udp_port: 47808,
  is_bbmd: false,
  is_foreign_device: false,
  bdt: [],
  fdt: [],
  seen_via: "manual",
  last_seen_at: null,
  notes: "",
  tags: {},
  custom_fields: {},
  created_at: ts,
  modified_at: ts,
};
const OTDEV = {
  id: "d1",
  ip_address_id: "ip",
  address: "10.0.1.1",
  subnet_id: "s1",
  ot_protocol: "modbus",
  ot_role: null,
  profinet_device_name: "",
  ot_vendor: "",
  ot_product: "",
  ot_serial: "",
  firmware_rev: "",
  purdue_level: null,
  cell_area: "",
  seen_via: "manual",
  last_seen_at: null,
  notes: "",
  tags: {},
  custom_fields: {},
  created_at: ts,
  modified_at: ts,
  zone_id: null,
  zone_name: "",
};
const OTZONE = {
  id: "z1",
  subnet_id: "s1",
  subnet_network: "10.0.1.0/24",
  purdue_level: "1",
  cell_area: "",
  name: "zone-one",
  notes: "",
  created_at: ts,
  modified_at: ts,
};

// api name -> method -> result
const LISTS: Record<string, Record<string, unknown>> = {
  avApi: {
    listFlows: { items: [FLOW], total: 1, limit: 50, offset: 0 },
    listReservedRanges: [RANGE],
  },
  bacnetApi: {
    listDevices: { items: [BACNET], total: 1, limit: 50, offset: 0 },
    listBbmds: [],
  },
  otApi: {
    listDevices: { items: [OTDEV], total: 1, limit: 50, offset: 0 },
    listZones: [OTZONE],
  },
};
const REMOVERS: Record<string, string[]> = {
  avApi: ["removeFlow", "removeReservedRange"],
  bacnetApi: ["removeDevice"],
  otApi: ["removeDevice", "removeZone"],
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const refuse = async () => {
    throw Object.assign(new Error("409"), {
      response: { status: 409, data: { detail: DETAIL } },
    });
  };
  const stubs = Object.fromEntries(
    Object.entries(actual)
      .filter(([name, v]) => name.endsWith("Api") && typeof v === "object")
      .map(([name]) => [
        name,
        new Proxy(
          {},
          {
            get: (_t, method) => {
              if (typeof method === "symbol") return undefined;
              if (name === "authApi" && method === "myPermissions")
                return async () => ({ is_superadmin: true, grants: [] });
              if (name === "featureModulesApi" && method === "list")
                return async () =>
                  ["network.bacnet", "network.av", "network.ot"].map((id) => ({
                    id,
                    label: id,
                    group: "x",
                    description: "",
                    default_enabled: true,
                    enabled: true,
                    requires: [],
                  }));
              if (LISTS[name] && method in LISTS[name])
                return async () => {
                  const key = `${name}.${method}`;
                  listCalls[key] = (listCalls[key] ?? 0) + 1;
                  return LISTS[name][method as string];
                };
              if (REMOVERS[name]?.includes(method as string)) return refuse;
              return pending;
            },
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { BACnetDevicesPage } = await import("./BACnetDevicesPage");
const { AVFlowsPage } = await import("./AVFlowsPage");
const { OTDevicesPage } = await import("./OTDevicesPage");

afterEach(cleanup);

function mount(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const CASES = [
  ["BACnet device", BACnetDevicesPage, "Delete device", "Delete"],
  ["AV flow", AVFlowsPage, "Remove AV flow", "Remove"],
  ["AV reserved range", AVFlowsPage, "Delete reserved range", "Delete"],
  ["OT descriptor", OTDevicesPage, "Delete descriptor", "Delete"],
  ["OT zone", OTDevicesPage, "Delete zone", "Delete"],
] as const;

describe("a refused registry delete (#3822)", () => {
  it.each(CASES)(
    "%s keeps the confirm open and says why",
    async (_n, Page, trigger, confirm) => {
      mount(<Page />);
      fireEvent.click(await screen.findByTitle(trigger));
      const buttons = await screen.findAllByRole("button", { name: confirm });
      fireEvent.click(buttons[buttons.length - 1]);
      await waitFor(() =>
        expect(screen.getByRole("alert").textContent).toContain(DETAIL),
      );
      // The confirm is still there to retry or cancel.
      expect(screen.getAllByRole("button", { name: "Cancel" }).length).toBe(1);
    },
  );
});
