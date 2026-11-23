/**
 * @vitest-environment jsdom
 *
 * The group mapping editor reads the mapping fresh when Edit opens and sends
 * only the field that was changed.
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

const updateMapping = vi.fn();
const PROVIDER = {
  id: "ap1",
  name: "corp-radius",
  type: "radius",
  is_enabled: false,
  priority: 10,
  config: { host: "192.0.2.5", port: 1812 },
  has_secrets: true,
  auto_create_users: false,
  auto_update_users: false,
  mapping_count: 1,
  created_at: "2026-10-23T00:00:00Z",
  modified_at: "2026-10-23T00:00:00Z",
};
const mapping = (gid: string, gname: string) => ({
  id: "m1",
  provider_id: "ap1",
  external_group: "ops",
  internal_group_id: gid,
  internal_group_name: gname,
  priority: 0,
});
// The list the page loaded holds the old target; the next read holds the one
// another session stored.
let reads = 0;
let gone = false;

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => ({ is_superadmin: true }) },
    authProvidersApi: {
      ...actual.authProvidersApi,
      list: async () => [PROVIDER],
      listMappings: async () =>
        reads++ === 0
          ? [mapping("g1", "Viewers")]
          : gone
            ? []
            : [mapping("g2", "Editors")],
      updateMapping: (...a: unknown[]) => updateMapping(...a),
    },
    groupsApi: {
      ...actual.groupsApi,
      list: async () => [
        { id: "g1", name: "Viewers" },
        { id: "g2", name: "Editors" },
      ],
    },
  };
});

const { AuthProvidersPage } = await import("./AuthProvidersPage");

afterEach(() => {
  cleanup();
  updateMapping.mockReset();
  reads = 0;
  gone = false;
});

describe("group mapping Edit", () => {
  it("reads the mapping fresh and sends only the changed field", async () => {
    updateMapping.mockResolvedValue(mapping("g2", "Editors"));
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <MemoryRouter>
          <AuthProvidersPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.click(await screen.findByTitle(/Edit/));
    // The provider dialog's mapping row.
    await screen.findAllByText("Viewers");
    const rows = await screen.findAllByTitle("Edit");
    expect(rows.length).toBeGreaterThan(1);
    fireEvent.click(rows[rows.length - 1]);
    const input = await screen.findByDisplayValue("ops");
    fireEvent.change(input, { target: { value: "ops-team" } });
    const row = input.closest("tr") as HTMLElement;
    fireEvent.click(within(row).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updateMapping).toHaveBeenCalledTimes(1));
    expect(updateMapping).toHaveBeenCalledWith("ap1", "m1", {
      external_group: "ops-team",
    });
  });

  it("shows an error and does not open when the mapping was deleted", async () => {
    gone = true;
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <MemoryRouter>
          <AuthProvidersPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.click(await screen.findByTitle(/Edit/));
    await screen.findAllByText("Viewers");
    const rows = await screen.findAllByTitle("Edit");
    fireEvent.click(rows[rows.length - 1]);
    await screen.findByText(/may have been deleted/);
    expect(screen.queryByDisplayValue("ops")).toBeNull();
    expect(updateMapping).not.toHaveBeenCalled();
  });
});
