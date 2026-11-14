/**
 * @vitest-environment jsdom
 *
 * #3737: Apply / Detach / bulk Apply / the Edit dialog's scope section change only THIS group's
 * membership, sent as deltas — never the whole set built from the tab's copy.
 */
import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";

const updateAssignments = vi.fn();
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
      updateAssignments: (...a: unknown[]) => updateAssignments(...a),
    },
    dnsApi: {
      ...actual.dnsApi,
      listViews: () => Promise.resolve([]),
      listServers: () => Promise.resolve([]),
    },
  };
});

import { BlocklistModal, BlocklistsTab } from "./DNSPage";

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

  it("an untouched Edit Save sends nothing that replaces a set", async () => {
    updateAssignments.mockResolvedValue({});
    const l = mkList("l1", "ads-list", ["g1", "g2"]);
    get.mockResolvedValue(l);
    const onClose = vi.fn();
    wrap(
      <BlocklistModal
        list={l as never}
        scope={{ group, views: [] }}
        onClose={onClose}
      />,
    );
    await userEvent.click(await screen.findByRole("button", { name: /^Save/ }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateAssignments).not.toHaveBeenCalled();
  });

  it("row Detach sends a remove delta for this group only", async () => {
    // The tab's copy says g1 only; another client has since attached g2.
    list.mockResolvedValue([mkList("l1", "ads-list", ["g1"])]);
    updateAssignments.mockResolvedValue({});
    wrap(<BlocklistsTab group={group} />);
    await screen.findByText("ads-list");
    await userEvent.click(
      screen.getAllByRole("button", { name: /^Detach$/ })[0],
    );
    await waitFor(() => expect(updateAssignments).toHaveBeenCalled());
    expect(updateAssignments).toHaveBeenCalledWith("l1", {
      remove_server_group_ids: ["g1"],
    });
  });

  it("bulk Apply and bulk Detach send per-list deltas", async () => {
    list.mockResolvedValue([
      mkList("l1", "applied-list", ["g1", "g2"]),
      mkList("l2", "other-list", ["g3"]),
    ]);
    updateAssignments.mockResolvedValue({});
    wrap(<BlocklistsTab group={group} />);
    await screen.findByText("applied-list");
    for (const name of ["applied-list", "other-list"]) {
      const row = screen.getByText(name).closest("div")!;
      await userEvent.click(within(row).getByRole("checkbox"));
    }
    await userEvent.click(
      screen.getByRole("button", { name: /^Apply \(1\)$/ }),
    );
    await waitFor(() => expect(updateAssignments).toHaveBeenCalledTimes(1));
    expect(updateAssignments).toHaveBeenCalledWith("l2", {
      add_server_group_ids: ["g1"],
    });

    updateAssignments.mockClear();
    for (const name of ["applied-list", "other-list"]) {
      const row = screen.getByText(name).closest("div")!;
      const box = within(row).getByRole("checkbox") as HTMLInputElement;
      if (!box.checked) await userEvent.click(box);
    }
    await userEvent.click(
      screen.getByRole("button", { name: /^Detach \(1\)$/ }),
    );
    await waitFor(() => expect(updateAssignments).toHaveBeenCalledTimes(1));
    expect(updateAssignments).toHaveBeenCalledWith("l1", {
      remove_server_group_ids: ["g1"],
    });
  });

  it("Edit's scope section sends only the view ticks that changed", async () => {
    updateAssignments.mockResolvedValue({});
    const views = [
      { id: "v1", name: "inside", group_id: "g1", match_clients: [] },
      { id: "v2", name: "outside", group_id: "g1", match_clients: [] },
    ];
    const l = {
      ...mkList("l1", "ads-list", ["g2"]),
      applied_view_ids: ["v1", "v-other-group"],
    };
    get.mockResolvedValue(l);
    wrap(
      <BlocklistModal
        list={l as never}
        scope={{ group, views: views as never }}
        onClose={() => {}}
      />,
    );
    await userEvent.click(
      await screen.findByRole("checkbox", { name: /inside/ }),
    );
    await userEvent.click(screen.getByRole("checkbox", { name: /outside/ }));
    await userEvent.click(screen.getByRole("button", { name: /^Save/ }));
    await waitFor(() => expect(updateAssignments).toHaveBeenCalled());
    expect(updateAssignments).toHaveBeenCalledWith("l1", {
      add_view_ids: ["v2"],
      remove_view_ids: ["v1"],
    });
  });
});
