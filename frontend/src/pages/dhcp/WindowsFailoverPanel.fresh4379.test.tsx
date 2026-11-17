/**
 * @vitest-environment jsdom
 *
 * The failover relationship Edit dialog reads the relationship when it opens
 * and a Save sends only what the operator changed (#4379). Before, it sent
 * every tuning value, so Windows was told to set what another client had
 * changed since the page loaded.
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

const h = vi.hoisted(() => ({ update: vi.fn() }));

const side = {
  server_id: "a",
  server_name: "dhcp1",
  partner_server: "dhcp2",
  partner_server_id: "b",
  server_role: null,
  state: "Normal",
  load_balance_percent: 50,
  reserve_percent: null,
  modified_at: "2026-10-01T00:00:00Z",
};
const rel = (lb: number, mclt: number) => ({
  name: "dhcp1-dhcp2",
  mode: "LoadBalance",
  max_client_lead_time_seconds: mclt,
  state_switch_interval_seconds: null,
  auto_state_transition: false,
  enable_auth: false,
  scope_ids: ["10.1.2.0"],
  sides: [{ ...side, load_balance_percent: lb }],
  complete: true,
  partner_outside_group: null,
});
const group = (r: ReturnType<typeof rel>) => ({
  group_id: "g-1",
  windows_member_count: 2,
  kea_members: [],
  members: [],
  relationships: [r],
  scopes: [],
});

vi.mock("./windowsFailover", () => ({
  GROUP_FAILOVER_QUERY_KEY: "dhcp-group-failover",
  useGroupFailover: () => ({ data: group(rel(50, 3600)), isLoading: false }),
}));
vi.mock("@/lib/api", () => ({
  dhcpApi: {
    // Another client changed the share and the lead time since the page loaded.
    getGroupFailover: async () => group(rel(70, 1800)),
    updateFailoverRelationship: (...a: unknown[]) => {
      h.update(...a);
      return Promise.resolve({ failover: group(rel(30, 1800)) });
    },
  },
}));
vi.mock("@/hooks/usePermissions", () => ({
  usePermissions: () => ({ isSuperadmin: true, can: () => true }),
}));

const { WindowsFailoverPanel } = await import("./WindowsFailoverPanel");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

async function openEdit() {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <WindowsFailoverPanel groupId="g-1" />
    </QueryClientProvider>,
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Edit" }, { timeout: 10000 }),
  );
  return screen.findByDisplayValue("70", {}, { timeout: 10000 });
}

describe(
  "Failover relationship Edit reads the row and saves only the change",
  { timeout: 30000 },
  () => {
    it("shows the values stored since the page loaded", async () => {
      await openEdit();
      expect(screen.getByDisplayValue("1800")).toBeTruthy();
    });

    it("an unrelated Save sends only that field", async () => {
      const share = await openEdit();
      fireEvent.change(share, { target: { value: "30" } });
      fireEvent.click(screen.getByRole("button", { name: "Save" }));
      await waitFor(() => expect(h.update).toHaveBeenCalled(), {
        timeout: 10000,
      });
      expect(h.update).toHaveBeenCalledWith("g-1", "dhcp1-dhcp2", {
        load_balance_percent: 30,
        server_id: "a",
      });
    });

    it("an untouched Save sends nothing", async () => {
      await openEdit();
      fireEvent.click(screen.getByRole("button", { name: "Save" }));
      await waitFor(
        () => expect(screen.queryByRole("button", { name: "Save" })).toBeNull(),
        { timeout: 10000 },
      );
      expect(h.update).not.toHaveBeenCalled();
    });
  },
);
