/**
 * @vitest-environment jsdom
 *
 * Edit Router / VLAN / VRF / ASN read the object when they open and send only
 * what the operator changed (#3869), the #3863 pattern. The page holds a stale
 * copy while the API holds what another client stored since.
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
import type { ASNRead, Router, VLAN, VRF } from "@/lib/api";

const STAMP = "2026-11-05T00:00:00Z";
const staleRouter: Router = {
  id: "r1",
  name: "edge",
  description: "old",
  location: "",
  management_ip: null,
  vendor: null,
  model: null,
  notes: "",
  created_at: STAMP,
  modified_at: STAMP,
};
const freshRouter: Router = { ...staleRouter, vendor: "theirs" };
const staleVlan: VLAN = {
  id: "v1",
  router_id: "r1",
  vlan_id: 10,
  name: "users",
  description: "old",
  created_at: STAMP,
  modified_at: STAMP,
};
const freshVlan: VLAN = { ...staleVlan, name: "theirs" };
const staleVrf: VRF = {
  id: "f1",
  name: "blue",
  description: "old",
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
const freshVrf: VRF = { ...staleVrf, route_distinguisher: "65000:1" };
const staleAsn = {
  id: "a1",
  number: 65001,
  name: "n",
  description: "old",
  kind: "private",
  holder_org: null,
  registry: "unknown",
  whois_last_checked_at: null,
  whois_data: null,
  whois_state: "n/a",
  customer_id: null,
  provider_id: null,
  tags: {},
  custom_fields: {},
  created_at: STAMP,
  modified_at: STAMP,
} as unknown as ASNRead;
const freshAsn = { ...staleAsn, holder_org: "theirs" } as ASNRead;

const updateRouter = vi.fn((_i: string, _b: unknown) =>
  Promise.resolve(freshRouter),
);
const updateVlan = vi.fn((_i: string, _b: unknown) =>
  Promise.resolve(freshVlan),
);
const updateVrf = vi.fn((_i: string, _b: unknown) => Promise.resolve(freshVrf));
const updateAsn = vi.fn((_i: string, _b: unknown) => Promise.resolve(freshAsn));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    vlansApi: {
      ...actual.vlansApi,
      getRouter: () => Promise.resolve(freshRouter),
      updateRouter: (i: string, b: unknown) => updateRouter(i, b),
      getVlan: () => Promise.resolve(freshVlan),
      updateVlan: (i: string, b: unknown) => updateVlan(i, b),
    },
    vrfsApi: {
      ...actual.vrfsApi,
      get: () => Promise.resolve(freshVrf),
      update: (i: string, b: unknown) => updateVrf(i, b),
    },
    asnsApi: {
      ...actual.asnsApi,
      list: () => Promise.resolve({ items: [], total: 0 }),
      get: () => Promise.resolve(freshAsn),
      update: (i: string, b: unknown) => updateAsn(i, b),
    },
  };
});

const { EditRouterModal, EditVLANModal } = await import("./vlans/VLANsPage");
const { VRFEditorModal } = await import("./vrfs/VRFsPage");
const { AsnFormModal } = await import("./network/AsnFormModal");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function open(ui: React.ReactNode) {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

async function editDescription(next: string) {
  const desc = await screen.findByDisplayValue("old");
  fireEvent.change(desc, { target: { value: next } });
  fireEvent.click(screen.getByRole("button", { name: /^save/i }));
}

describe("#3869", () => {
  it("Edit Router sends only the Description, not the Vendor another client set", async () => {
    open(<EditRouterModal router={staleRouter} onClose={() => {}} />);
    await editDescription("new");
    await waitFor(() => expect(updateRouter).toHaveBeenCalled());
    expect(updateRouter).toHaveBeenCalledWith("r1", { description: "new" });
  });

  it("Edit VLAN sends only the Description, not the Name another client set", async () => {
    open(<EditVLANModal vlan={staleVlan} routerId="r1" onClose={() => {}} />);
    await editDescription("new");
    await waitFor(() => expect(updateVlan).toHaveBeenCalled());
    expect(updateVlan).toHaveBeenCalledWith("v1", { description: "new" });
  });

  it("Edit VRF sends only the Description, not the RD another client set", async () => {
    open(<VRFEditorModal existing={staleVrf} onClose={() => {}} />);
    await editDescription("new");
    await waitFor(() => expect(updateVrf).toHaveBeenCalled());
    expect(updateVrf).toHaveBeenCalledWith("f1", { description: "new" });
  });

  it("Edit ASN sends only the Description, not the Holder another client set", async () => {
    open(<AsnFormModal asn={staleAsn} onClose={() => {}} />);
    await editDescription("new");
    await waitFor(() => expect(updateAsn).toHaveBeenCalled());
    expect(updateAsn).toHaveBeenCalledWith("a1", { description: "new" });
  });
});
