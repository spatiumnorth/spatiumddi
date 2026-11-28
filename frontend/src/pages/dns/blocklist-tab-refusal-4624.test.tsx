/**
 * @vitest-environment jsdom
 *
 * #4624: the Blocking Lists tab's Apply (row and bulk) shows the server's
 * refusal; the scope dialog drops the amber "does not render RPZ" note when
 * the red one shows; unapplied_warning is shown on the tab and the detail.
 */
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";

const update = vi.fn();
const list = vi.fn();
const listServers = vi.fn();

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
      get: () => Promise.resolve(mkList("l1", "ads-list")),
      updateAssignments: (...a: unknown[]) => update(...a),
      listEntries: () => Promise.resolve({ items: [], total: 0 }),
      listExceptions: () => Promise.resolve([]),
    },
    dnsApi: {
      ...actual.dnsApi,
      listViews: () => Promise.resolve([]),
      listServers: (...a: unknown[]) => listServers(...a),
    },
  };
});

import { BlocklistDetail, BlocklistModal, BlocklistsTab } from "./DNSPage";

const group = { id: "g1", name: "Group1" } as never;
const mkList = (id: string, name: string, extra = {}) => ({
  id,
  name,
  description: "",
  category: "ads",
  source_type: "manual",
  feed_url: null,
  block_mode: "nxdomain",
  enabled: true,
  entry_count: 0,
  applied_group_ids: [] as string[],
  applied_view_ids: [],
  feed_wildcard_mode: "by_syntax",
  feed_parse_skipped: null,
  last_synced_at: null,
  last_sync_status: null,
  last_sync_error: null,
  created_at: "2026-01-01T00:00:00Z",
  modified_at: "2026-01-01T00:00:00Z",
  ...extra,
});
const refused = (msg: string) =>
  Promise.reject(
    Object.assign(new Error("422"), {
      response: { status: 422, data: { detail: msg } },
    }),
  );
const wrap = (ui: React.ReactElement) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
};

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("Blocking Lists tab Apply (#4624)", () => {
  it("row Apply shows the 422 detail and keeps the list unapplied", async () => {
    list.mockResolvedValue([mkList("l1", "ads-list")]);
    update.mockImplementation(() => refused("Group runs PowerDNS: no RPZ"));
    wrap(<BlocklistsTab group={group} />);
    await screen.findByText("ads-list");
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toContain(
        "ads-list: Group runs PowerDNS: no RPZ",
      ),
    );
    expect(screen.getByText("Available (not applied)")).toBeTruthy();
  });

  it("bulk Apply reports the refused list and the one that applied", async () => {
    list.mockResolvedValue([mkList("l1", "ok-list"), mkList("l2", "bad-list")]);
    update.mockImplementation((id: string) =>
      id === "l2" ? refused("no capable server") : Promise.resolve({}),
    );
    wrap(<BlocklistsTab group={group} />);
    await screen.findByText("ok-list");
    for (const name of ["ok-list", "bad-list"]) {
      const row = screen.getByText(name).closest("div")!;
      await userEvent.click(row.querySelector("input[type=checkbox]")!);
    }
    await userEvent.click(screen.getByRole("button", { name: /^Apply \(2\)/ }));
    await waitFor(() => {
      const t = screen.getByRole("alert").textContent ?? "";
      expect(t).toContain("1 applied, 1 refused");
      expect(t).toContain("bad-list: no capable server");
      expect(t).not.toContain("ok-list:");
    });
  });

  it("shows unapplied_warning on an applied list row", async () => {
    list.mockResolvedValue([
      mkList("l1", "ads-list", {
        applied_group_ids: ["g1"],
        unapplied_warning: "Applied to a group with no RPZ server",
      }),
    ]);
    wrap(<BlocklistsTab group={group} />);
    await screen.findByText("Applied to a group with no RPZ server");
  });

  it("shows unapplied_warning on the list detail", async () => {
    wrap(
      <BlocklistDetail
        list={
          mkList("l1", "ads-list", {
            unapplied_warning: "Applied to a group with no RPZ server",
          }) as never
        }
        onBack={() => {}}
      />,
    );
    await screen.findByText("Applied to a group with no RPZ server");
  });
});

describe("scope dialog notices (#4624)", () => {
  const open = () =>
    wrap(
      <BlocklistModal
        list={mkList("l1", "ads-list") as never}
        scope={{ group, views: [] }}
        onClose={() => {}}
      />,
    );

  it("PowerDNS-only group: red notice, no amber note", async () => {
    listServers.mockResolvedValue([{ id: "s1", driver: "powerdns" }]);
    open();
    await screen.findByText(/a blocklist here blocks/);
    expect(
      screen.queryByText(/Scoping affects the BIND9 servers only/),
    ).toBeNull();
  });

  it("mixed group keeps the amber note", async () => {
    listServers.mockResolvedValue([
      { id: "s1", driver: "bind9" },
      { id: "s2", driver: "powerdns" },
    ]);
    open();
    await screen.findByText(/Scoping affects the BIND9 servers only/);
    expect(screen.queryByText(/a blocklist here blocks/)).toBeNull();
  });
});
