/**
 * @vitest-environment jsdom
 *
 * A refused Poll Now, device Active switch, overlay-site Detach and Stale IPs
 * Deprecate each say so, in the server's words (#2522). Detach and Deprecate
 * keep their confirm open instead of closing as if they had worked.
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
import { MemoryRouter, Route, Routes } from "react-router-dom";
import type { ReactNode } from "react";

function refusal(detail: string) {
  return Object.assign(new Error("Request failed with status code 403"), {
    response: { status: 403, data: { detail } },
  });
}

const DEVICE = {
  id: "d1",
  name: "core-sw",
  hostname: "core-sw.example",
  ip_address: "192.0.2.10",
  device_type: "switch",
  description: null,
  vendor: null,
  is_active: true,
  snmp_version: "v2c",
  tags: {},
  custom_fields: {},
  last_poll_status: null,
  last_poll_at: null,
} as never;

const SITE = {
  id: "s1",
  overlay_network_id: "o1",
  site_id: "site-1",
  role: "hub",
  device_id: null,
  loopback_subnet_id: null,
  preferred_circuits: [],
  notes: "",
  created_at: "2026-10-22T00:00:00Z",
  modified_at: "2026-10-22T00:00:00Z",
} as never;

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise<never>(() => {});
  return {
    ...actual,
    networkApi: {
      ...actual.networkApi,
      getDevice: () => Promise.resolve(DEVICE),
      listDevices: () =>
        Promise.resolve({ items: [DEVICE], total: 1, page: 1, page_size: 50 }),
      pollNow: () => Promise.reject(refusal("Permission denied: poll")),
      updateDevice: () => Promise.reject(refusal("Permission denied: update")),
    },
    overlaysApi: {
      ...actual.overlaysApi,
      get: () =>
        Promise.resolve({
          id: "o1",
          name: "wan",
          site_count: 1,
          policy_count: 0,
        } as never),
      listSites: () => Promise.resolve([SITE]),
      detachSite: () =>
        Promise.reject(
          refusal("Permission denied: need 'delete' on 'overlay_network'"),
        ),
    },
    sitesApi: { ...actual.sitesApi, list: pending },
    circuitsApi: { ...actual.circuitsApi, list: pending },
    ipamApi: {
      ...actual.ipamApi,
      listSpaces: () => Promise.resolve([]),
      getStaleIPs: () =>
        Promise.resolve({
          generated_at: "2026-10-22T00:00:00Z",
          stale_days: 30,
          include_never_seen: false,
          total: 1,
          limit: 50,
          offset: 0,
          entries: [
            {
              id: "ip1",
              address: "192.0.2.5",
              status: "allocated",
              hostname: null,
              mac_address: null,
              last_seen_at: null,
              last_seen_method: null,
              days_stale: 40,
              subnet_id: "sn1",
              subnet_network: "192.0.2.0/24",
              subnet_name: "lab",
            },
          ],
        } as never),
      deprecateStaleIPs: () =>
        Promise.reject(refusal("Permission denied: deprecate")),
    },
  };
});

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

import { DeviceDetailView } from "./DeviceDetailView";
import { NetworkPage } from "./NetworkPage";
import { OverlayDetailPage } from "./OverlayDetailPage";
import { StaleIPReportPage } from "../ipam/StaleIPReportPage";

function show(ui: ReactNode, path: string, route = path) {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path={route} element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
afterEach(cleanup);

describe("refused actions say so (#2522)", () => {
  it("Poll Now", async () => {
    show(<DeviceDetailView />, "/network/devices/d1", "/network/devices/:id");
    fireEvent.click(await screen.findByRole("button", { name: /Poll Now/ }));
    await screen.findByText(/Permission denied: poll/);
  });

  it("the device Active box", async () => {
    show(<NetworkPage />, "/network");
    const boxes = await screen.findAllByRole("checkbox");
    const active = boxes[boxes.length - 1];
    fireEvent.click(active);
    await screen.findByText(/Permission denied: update/);
  });

  it("overlay site Detach stays open and says why", async () => {
    show(
      <OverlayDetailPage />,
      "/network/overlays/o1",
      "/network/overlays/:id",
    );
    fireEvent.click(await screen.findByRole("button", { name: /^Sites/ }));
    fireEvent.click(await screen.findByTitle("Detach"));
    const detach = await screen.findAllByRole("button", { name: "Detach" });
    fireEvent.click(detach[detach.length - 1]);
    await screen.findByText(/need 'delete' on 'overlay_network'/);
    expect(screen.getByText("Detach site")).toBeTruthy();
  });

  it("Stale IPs Deprecate stays open and says why", async () => {
    show(<StaleIPReportPage />, "/ipam/stale");
    await screen.findByText("192.0.2.5");
    const boxes = screen.getAllByRole("checkbox");
    fireEvent.click(boxes[boxes.length - 1]);
    fireEvent.click(
      await screen.findByRole("button", { name: /Deprecate selected/ }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Deprecate 1" }));
    await waitFor(() =>
      expect(document.body.textContent).toContain(
        "Permission denied: deprecate",
      ),
    );
    expect(screen.getByText("Deprecate stale IPs?")).toBeTruthy();
  });
});
