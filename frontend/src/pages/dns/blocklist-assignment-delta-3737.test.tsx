/**
 * @vitest-environment jsdom
 *
 * #3737: Apply / Detach / bulk Apply / Save scope change only THIS group's
 * membership, sent as deltas — never the whole set built from the tab's copy.
 */
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";

const updateAssignments = vi.fn();
const list = vi.fn();

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
      updateAssignments: (...a: unknown[]) => updateAssignments(...a),
    },
    dnsApi: {
      ...actual.dnsApi,
      listViews: () => Promise.resolve([]),
      listServers: () => Promise.resolve([]),
    },
  };
});

import { BlocklistScopeModal, BlocklistsTab } from "./DNSPage";

const group = { id: "g1", name: "Group1" } as never;
const mkList = (id: string, name: string, groups: string[]) => ({
  id,
  name,
  description: "",
  category: "ads",
  source_type: "manual",
  feed_url: null,
  block_mode: "nxdomain",
  enabled: true,
  entry_count: 0,
  applied_group_ids: groups,
  applied_view_ids: [],
  feed_entries_are_wildcard: true,
  feed_parse_skipped: null,
  last_synced_at: null,
  last_sync_status: null,
  last_sync_error: null,
  created_at: "2026-01-01T00:00:00Z",
  modified_at: "2026-01-01T00:00:00Z",
});

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("blocklist assignment deltas (#3737)", () => {
  it("row Apply sends an add delta, not the tab's copy of the set", async () => {
    // The tab's copy says only g2; another client has since attached g3.
    list.mockResolvedValue([mkList("l1", "ads-list", ["g2"])]);
    updateAssignments.mockResolvedValue({});
    wrap(<BlocklistsTab group={group} />);
    await screen.findByText("ads-list");
    await userEvent.click(
      screen.getAllByRole("button", { name: /^Apply$/ })[0],
    );
    await waitFor(() => expect(updateAssignments).toHaveBeenCalled());
    expect(updateAssignments).toHaveBeenCalledWith("l1", {
      add_server_group_ids: ["g1"],
    });
  });

  it("an untouched Save scope sends nothing that replaces a set", async () => {
    updateAssignments.mockResolvedValue({});
    wrap(
      <BlocklistScopeModal
        list={mkList("l1", "ads-list", ["g1", "g2"]) as never}
        group={group}
        views={[]}
        onClose={() => {}}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: /Save scope/ }));
    await waitFor(() => expect(updateAssignments).toHaveBeenCalled());
    expect(updateAssignments).toHaveBeenCalledWith("l1", {});
  });
});
