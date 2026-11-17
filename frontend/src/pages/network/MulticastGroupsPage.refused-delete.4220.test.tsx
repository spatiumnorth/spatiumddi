/**
 * @vitest-environment jsdom
 *
 * A refused Delete on the Multicast groups list says why in an announced line
 * and reads the list again (#4220); the confirm used to close at the press
 * and the row stayed with no word.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const api = { list: vi.fn(), remove: vi.fn() };

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const stub = (name: string, extra: Record<string, unknown>) =>
    new Proxy(
      { ...(actual as Record<string, any>)[name], ...extra },
      {
        get: (t, m) =>
          m in t
            ? t[m as string]
            : typeof m === "symbol"
              ? undefined
              : async () => [],
      },
    );
  return {
    ...actual,
    ipamApi: stub("ipamApi", { listSpaces: async () => [] }),
    customersApi: stub("customersApi", {
      list: async () => ({ items: [], total: 0 }),
    }),
    multicastApi: stub("multicastApi", {
      list: (...a: unknown[]) => api.list(...a),
      remove: (...a: unknown[]) => api.remove(...a),
    }),
  };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => false }),
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

const { MulticastGroupsPage } = await import("./MulticastGroupsPage");

const group = {
  id: "g1",
  space_id: "sp",
  address: "239.1.1.1",
  name: "grp",
  description: "",
  application: "",
  rtp_payload_type: null,
  bandwidth_mbps_estimate: null,
  vlan_id: null,
  customer_id: null,
  service_id: null,
  domain_id: null,
  tags: {},
  custom_fields: {},
  created_at: "",
  modified_at: "",
};

afterEach(() => {
  cleanup();
  api.list.mockReset();
  api.remove.mockReset();
});

describe("a refused multicast group delete (#4220)", () => {
  it("announces why and reads the list again", async () => {
    api.list.mockResolvedValue({
      items: [group],
      total: 1,
      limit: 50,
      offset: 0,
    });
    api.remove.mockRejectedValue(
      Object.assign(new Error("404"), {
        response: {
          status: 404,
          data: { detail: "Multicast group not found" },
        },
      }),
    );
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <MulticastGroupsPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));
    const dialog = await screen.findByRole("dialog");
    const before = api.list.mock.calls.length;
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toContain(
        "Multicast group not found",
      ),
    );
    await waitFor(() =>
      expect(api.list.mock.calls.length).toBeGreaterThan(before),
    );
  });
});
