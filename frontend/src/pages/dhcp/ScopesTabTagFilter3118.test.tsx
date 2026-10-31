/**
 * @vitest-environment jsdom
 *
 * #3118 — under a tag chip that matches none of the group's scopes, the
 * Scopes tab says the filter matched none and its subnet picker still
 * knows the group serves the hidden scope's subnet.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const scope = (id: string, subnet_id: string) => ({
  id,
  name: id,
  subnet_id,
  group_id: "g1",
  address_family: "ipv4",
});
// The group's scopes, per test; a tag chip matches none of them.
const fixture: { scopes: ReturnType<typeof scope>[]; fail: boolean } = {
  scopes: [scope("s1", "n1")],
  fail: false,
};
const listScopesByGroup = vi.fn((_g: string, params?: { tag?: string[] }) =>
  fixture.fail
    ? Promise.reject(new Error("boom"))
    : Promise.resolve(params?.tag?.length ? [] : [...fixture.scopes]),
);

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
    },
    tagsApi: {
      ...actual.tagsApi,
      listKeys: () => Promise.resolve([]),
      listValues: () => Promise.resolve([]),
    },
    ipamApi: {
      ...actual.ipamApi,
      listSubnets: () =>
        Promise.resolve([
          { id: "n1", network: "10.31.1.0/24" },
          { id: "n2", network: "10.31.2.0/24" },
          { id: "n3", network: "10.31.3.0/24" },
        ]),
    },
    dhcpApi: {
      ...actual.dhcpApi,
      listScopesByGroup: (g: string, p?: { tag?: string[] }) =>
        listScopesByGroup(g, p),
      listGroups: () => Promise.resolve([]),
      getGroupFailover: () => Promise.resolve({ windows_member_count: 0 }),
    },
  };
});

import { ServerScopesTab } from "./DHCPPage";

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  fixture.scopes = [scope("s1", "n1")];
  fixture.fail = false;
});

function renderTab() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ServerScopesTab groupId="g1" />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return qc;
}

function addChip(value: string) {
  const input = screen.getByPlaceholderText(/Filter scopes by tag/);
  fireEvent.change(input, { target: { value } });
  fireEvent.keyDown(input, { key: "Enter" });
}

const pickerOptions = () =>
  screen
    .getAllByRole("option")
    .map((o) => o.textContent)
    .join("|");

describe("Scopes tab under a tag filter that matches nothing (#3118)", () => {
  it("says the filter matched none and keeps the served subnet out of the picker", async () => {
    renderTab();
    await screen.findByText("1 scope on this group.");
    addChip("nope");
    expect(
      await screen.findByText("0 of 1 scope matches the tag filter."),
    ).toBeTruthy();
    expect(
      screen.getByText("No scopes match the current tag filter."),
    ).toBeTruthy();
    expect(screen.queryByText(/No scopes on this server/)).toBeNull();
    expect(screen.queryByText(/0 scopes on this group/)).toBeNull();
    expect(pickerOptions()).not.toContain("10.31.1.0/24");
    expect(pickerOptions()).toContain("10.31.2.0/24");
  });

  it("uses the plural verb for more than one scope", async () => {
    fixture.scopes = [scope("s1", "n1"), scope("s2", "n2")];
    renderTab();
    await screen.findByText("2 scopes on this group.");
    addChip("nope");
    expect(
      await screen.findByText("0 of 2 scopes match the tag filter."),
    ).toBeTruthy();
  });

  it("fetches the group's scopes once when no chip is set", async () => {
    renderTab();
    await screen.findByText("1 scope on this group.");
    await act(async () => {});
    expect(listScopesByGroup).toHaveBeenCalledTimes(1);
  });

  it("offers no subnet while it cannot tell which ones the group serves", async () => {
    fixture.fail = true;
    renderTab();
    await screen.findByText("Could not load the group's scopes");
    expect(pickerOptions()).not.toContain("10.31.");
  });

  it("refreshes the unfiltered count when the scope list is invalidated", async () => {
    const qc = renderTab();
    await screen.findByText("1 scope on this group.");
    addChip("nope");
    await screen.findByText("0 of 1 scope matches the tag filter.");
    // A scope created elsewhere (CreateScopeModal invalidates this prefix).
    fixture.scopes = [scope("s1", "n1"), scope("s2", "n2")];
    await act(async () => {
      await qc.invalidateQueries({ queryKey: ["dhcp-scopes-group"] });
    });
    await screen.findByText("0 of 2 scopes match the tag filter.");
    await waitFor(() => expect(pickerOptions()).not.toContain("10.31.2.0/24"));
    expect(pickerOptions()).toContain("10.31.3.0/24");
  });
});
