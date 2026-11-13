/**
 * @vitest-environment jsdom
 *
 * #3822: the blocking lists' bulk delete reads every result. A refused delete
 * leaves its list in place, keeps the dialog open and says why; before, it
 * swallowed every rejection and closed as if all had worked.
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

const del = vi.fn();
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
      delete: (...a: unknown[]) => del(...a),
    },
    dnsApi: {
      ...actual.dnsApi,
      listViews: () => Promise.resolve([]),
      listServers: () => Promise.resolve([]),
    },
  };
});

import { BlocklistsTab } from "./DNSPage";

const group = { id: "g1", name: "Group1" } as never;
const mkList = (id: string, name: string) => ({
  id,
  name,
  description: "",
  category: "ads",
  source_type: "manual",
  feed_url: null,
  block_mode: "nxdomain",
  enabled: true,
  entry_count: 0,
  applied_group_ids: [],
  applied_view_ids: [],
  feed_entries_are_wildcard: true,
  feed_parse_skipped: null,
  last_synced_at: null,
  last_sync_status: null,
  last_sync_error: null,
  created_at: "2026-01-01T00:00:00Z",
  modified_at: "2026-01-01T00:00:00Z",
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("blocking lists bulk delete (#3822)", () => {
  it("says which delete was refused and why, and keeps the dialog open", async () => {
    list.mockResolvedValue([
      mkList("l1", "ok-list"),
      mkList("l2", "used-list"),
    ]);
    del.mockImplementation((id: string) =>
      id === "l2"
        ? Promise.reject(
            Object.assign(new Error("409"), {
              response: { status: 409, data: { detail: "List is in use" } },
            }),
          )
        : Promise.resolve({}),
    );
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <BlocklistsTab group={group} />
      </QueryClientProvider>,
    );
    await screen.findByText("ok-list");
    for (const name of ["ok-list", "used-list"]) {
      const row = screen.getByText(name).closest("div")!;
      await userEvent.click(within(row).getByRole("checkbox"));
    }
    await userEvent.click(
      screen.getByRole("button", { name: /^Delete \(2\)/ }),
    );
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    await userEvent.click(screen.getByLabelText(/I understand/));
    await userEvent.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toContain(
        "1 of 2 blocking lists were not deleted: List is in use",
      ),
    );
    expect(del).toHaveBeenCalledTimes(2);
  });
});
