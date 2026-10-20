/**
 * @vitest-environment jsdom
 *
 * New Devices "Block" with core.dhcp off (#2134): the DHCP half is gone, so
 * the action is hidden unless the upstream quarantine can still run, and then
 * it is relabelled and always sends block_upstream.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const mods = { off: new Set<string>() };
const block = vi.fn();

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    modules: [],
    ready: true,
    isLoading: false,
    isError: false,
    refetch: () => {},
    enabled: (id: string) => !mods.off.has(id),
  }),
}));

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return { ...actual, usePermissions: () => ({ can: () => true }) };
});

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const row = {
    id: "s1",
    ip_address_id: "a1",
    ip_address: "10.0.0.5",
    subnet_id: null,
    subnet_name: null,
    mac_address: "aa:bb:cc:dd:ee:ff",
    oui_vendor: null,
    classification: "new",
    source: "dhcp",
    is_randomized: false,
    first_seen: "2026-01-01T00:00:00Z",
    last_seen: "2026-01-01T00:00:00Z",
    acknowledged_at: null,
  };
  return {
    ...actual,
    ipamApi: { ...actual.ipamApi, listSubnets: async () => [] },
    newDeviceApi: {
      ...actual.newDeviceApi,
      summary: async () => ({
        new_count: 1,
        new_randomized_count: 0,
        new_last_24h: 1,
        acknowledged_count: 0,
        known_count: 0,
        allowlist_count: 0,
      }),
      listSightings: async () => ({
        items: [row],
        total: 1,
        page: 1,
        page_size: 50,
      }),
      block: (...a: unknown[]) => {
        block(...a);
        return Promise.resolve({
          mac_address: "aa:bb:cc:dd:ee:ff",
          blocked_group_ids: [],
          already_blocked_group_ids: [],
          upstream_block_created: true,
          upstream_change_request_id: null,
        });
      },
    },
  };
});

const { NewDevicesPage } = await import("./NewDevicesPage");

async function open() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>
        <NewDevicesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByText("10.0.0.5");
  const boxes = screen.getAllByRole("checkbox");
  fireEvent.click(boxes[boxes.length - 1]);
  await screen.findByText("1 selected");
}

beforeEach(() => {
  mods.off = new Set();
  block.mockReset();
});
afterEach(cleanup);

describe("New Devices block with DHCP off (#2134)", () => {
  it("offers the DHCP block while core.dhcp is on", async () => {
    await open();
    fireEvent.click(screen.getByRole("button", { name: /^Block$/ }));
    expect(screen.getByText(/can.t obtain a lease/)).toBeTruthy();
  });

  it("hides the action when DHCP and block-sync are both off", async () => {
    mods.off = new Set(["core.dhcp", "security.block_sync"]);
    await open();
    expect(
      screen.queryByRole("button", { name: /Block|Quarantine/ }),
    ).toBeNull();
  });

  it("relabels it and forces the upstream push when only block-sync is on", async () => {
    mods.off = new Set(["core.dhcp"]);
    await open();
    expect(screen.queryByRole("button", { name: /^Block$/ })).toBeNull();
    fireEvent.click(
      screen.getByRole("button", { name: "Quarantine upstream" }),
    );
    expect(screen.queryByText(/DHCP\s+server group/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /^Quarantine$/ }));
    await waitFor(() => expect(block).toHaveBeenCalled());
    expect(block.mock.calls[0][0].block_upstream).toBe(true);
  });
});
