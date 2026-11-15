/**
 * @vitest-environment jsdom
 *
 * #4182: the separate funnel (scope) button is gone; the Edit dialog holds the
 * view / group scoping and saves it through the assignments endpoint.
 */
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";

const updateAssignments = vi.fn();
const update = vi.fn();
const list = vi.fn();
const get = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
    },
    dnsBlocklistApi: {
      ...actual.dnsBlocklistApi,
      list: (...a: unknown[]) => list(...a),
      get: (...a: unknown[]) => get(...a),
      update: (...a: unknown[]) => update(...a),
      updateAssignments: (...a: unknown[]) => updateAssignments(...a),
    },
    dnsApi: {
      ...actual.dnsApi,
      listViews: () =>
        Promise.resolve([
          {
            id: "v1",
            name: "guest",
            group_id: "g1",
            match_clients: ["10.9.0.0/24"],
          },
        ]),
      listServers: () => Promise.resolve([]),
    },
  };
});

import { BlocklistsTab } from "./DNSPage";

const group = { id: "g1", name: "Group1" } as never;
const l = {
  id: "l1",
  name: "ads-list",
  description: "",
  category: "ads",
  source_type: "manual",
  feed_url: null,
  block_mode: "nxdomain",
  enabled: true,
  entry_count: 0,
  applied_group_ids: ["g1"],
  applied_view_ids: [],
  feed_entries_are_wildcard: true,
  feed_parse_skipped: null,
  last_synced_at: null,
  last_sync_status: null,
  last_sync_error: null,
  created_at: "2026-01-01T00:00:00Z",
  modified_at: "2026-01-01T00:00:00Z",
};

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function open() {
  list.mockResolvedValue([l]);
  get.mockResolvedValue(l);
  updateAssignments.mockResolvedValue({});
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <BlocklistsTab group={group} />
    </QueryClientProvider>,
  );
}

describe("blocklist scope lives in Edit (#4182)", () => {
  it("has no separate scope button", async () => {
    open();
    await screen.findByText("ads-list");
    await screen.findByRole("button", { name: /Edit blocking list/ });
    expect(
      screen.queryByRole("button", { name: /Scope to specific views/ }),
    ).toBeNull();
  });

  it("Edit shows the scoping and Save sends it", async () => {
    open();
    await userEvent.click(
      await screen.findByRole("button", { name: /Edit blocking list/ }),
    );
    const whole = await screen.findByRole("checkbox", { name: /Whole group/ });
    expect((whole as HTMLInputElement).checked).toBe(true);
    await userEvent.click(whole);
    await userEvent.click(screen.getByRole("checkbox", { name: /guest/ }));
    await userEvent.click(screen.getByRole("button", { name: /^Save/ }));
    await waitFor(() => expect(updateAssignments).toHaveBeenCalled());
    expect(updateAssignments).toHaveBeenCalledWith("l1", {
      remove_server_group_ids: ["g1"],
      add_view_ids: ["v1"],
    });
    expect(update).not.toHaveBeenCalled();
  });
});
