/**
 * @vitest-environment jsdom
 *
 * The BACnet device Edit dialog reads the device when it opens and a Save
 * sends only what the operator changed (#4379). Before, it seeded from the
 * click-time list row and PATCHed every field, so a value another client
 * stored since the list loaded was put back by an unrelated Save.
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

const h = vi.hoisted(() => ({ reads: 0, update: vi.fn() }));

const BASE = {
  id: "d1",
  ip_address_id: "ip1",
  subnet_id: null,
  address: "10.0.0.5",
  hostname: null,
  device_instance: 1001,
  vendor_id: null,
  vendor_name: "",
  vendor_label: null,
  device_name: "AHU old",
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
  created_at: "",
  modified_at: "",
};
const FRESH = {
  ...BASE,
  device_name: "AHU changed elsewhere",
  location: "Roof",
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    bacnetApi: {
      ...actual.bacnetApi,
      // The first read is the page's list; every later one is the dialog's.
      listDevices: () => {
        h.reads += 1;
        return Promise.resolve({
          items: [h.reads === 1 ? BASE : FRESH],
          total: 1,
          limit: 50,
          offset: 0,
        });
      },
      listBbmds: () => Promise.resolve([]),
      updateDevice: (...a: unknown[]) => {
        h.update(...a);
        return Promise.resolve(FRESH);
      },
    },
    ipamApi: { ...actual.ipamApi, listSubnets: () => Promise.resolve([]) },
  };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: true,
      isLoading: false,
    }),
  };
});

const { BACnetDevicesPage } = await import("./BACnetDevicesPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  h.reads = 0;
});

async function openEdit() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <BACnetDevicesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(
    await screen.findByTitle("Edit device", {}, { timeout: 10000 }),
  );
  return (await screen.findByDisplayValue(
    "AHU changed elsewhere",
    {},
    { timeout: 10000 },
  )) as HTMLInputElement;
}

describe("BACnet device Edit dialog (#4379)", { timeout: 30000 }, () => {
  it("shows what is stored now, not the click-time list row", async () => {
    const name = await openEdit();
    expect(name.value).toBe("AHU changed elsewhere");
    expect(screen.getByDisplayValue("Roof")).toBeTruthy();
  });

  it("an unrelated change sends only that field", async () => {
    const name = await openEdit();
    fireEvent.change(name, { target: { value: "AHU renamed" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(h.update).toHaveBeenCalledTimes(1), {
      timeout: 10000,
    });
    expect(h.update).toHaveBeenCalledWith("d1", { device_name: "AHU renamed" });
  });

  it("a Save with nothing changed sends nothing", async () => {
    await openEdit();
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(
      () =>
        expect(screen.queryByDisplayValue("AHU changed elsewhere")).toBeNull(),
      { timeout: 10000 },
    );
    expect(h.update).not.toHaveBeenCalled();
  });
});
