/**
 * @vitest-environment jsdom
 *
 * #4573: PowerDNS has no RPZ, so the scope fields of a PowerDNS-only group say
 * so and will not tick a new assignment; a BIND9 group is untouched.
 */
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";

const listServers = vi.fn();
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
      get: (...a: unknown[]) => get(...a),
    },
    dnsApi: {
      ...actual.dnsApi,
      listViews: () => Promise.resolve([]),
      listServers: (...a: unknown[]) => listServers(...a),
    },
  };
});

import { BlocklistModal } from "./DNSPage";

const group = { id: "g1", name: "Group1" } as never;
const list = {
  id: "l1",
  name: "ads-list",
  description: "",
  category: "ads",
  source_type: "manual",
  feed_url: null,
  block_mode: "nxdomain",
  enabled: true,
  entry_count: 0,
  applied_group_ids: [],
  applied_view_ids: [],
  feed_wildcard_mode: "by_syntax",
  feed_parse_skipped: null,
  last_synced_at: null,
  last_sync_status: null,
  last_sync_error: null,
  created_at: "2026-01-01T00:00:00Z",
  modified_at: "2026-01-01T00:00:00Z",
};

function open() {
  get.mockResolvedValue(list);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <BlocklistModal
        list={list as never}
        scope={{ group, views: [] }}
        onClose={() => {}}
      />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("blocklist scope on a PowerDNS group (#4573)", () => {
  it("warns and disables Whole group on a PowerDNS-only group", async () => {
    listServers.mockResolvedValue([{ id: "s1", driver: "powerdns" }]);
    open();
    await screen.findByText(/renders no blocklist, so a blocklist here blocks/);
    expect(
      (screen.getByLabelText(/Whole group/) as HTMLInputElement).disabled,
    ).toBe(true);
  });

  it("leaves a BIND9 group alone", async () => {
    listServers.mockResolvedValue([{ id: "s1", driver: "bind9" }]);
    open();
    const box = (await screen.findByLabelText(
      /Whole group/,
    )) as HTMLInputElement;
    expect(box.disabled).toBe(false);
    expect(
      screen.queryByText(/renders no blocklist, so a blocklist here/),
    ).toBeNull();
  });
});
