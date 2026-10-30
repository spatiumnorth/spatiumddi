/**
 * @vitest-environment jsdom
 *
 * #3118 — under a tag chip that matches none of the group's scopes, the
 * Scopes tab says the filter matched none and its subnet picker still
 * knows the group serves the hidden scope's subnet.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const scope = {
    id: "s1",
    name: "default",
    subnet_id: "n1",
    group_id: "g1",
    address_family: "ipv4",
  };
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
        ]),
    },
    dhcpApi: {
      ...actual.dhcpApi,
      listScopesByGroup: (_g: string, params?: { tag?: string[] }) =>
        Promise.resolve(params?.tag?.length ? [] : [scope]),
      listGroups: () => Promise.resolve([]),
    },
  };
});

import { ServerScopesTab } from "./DHCPPage";

afterEach(cleanup);

describe("Scopes tab under a tag filter that matches nothing (#3118)", () => {
  it("says the filter matched none and keeps the served subnet out of the picker", async () => {
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
    await screen.findByText("1 scope on this group.");
    const input = screen.getByPlaceholderText(/Filter scopes by tag/);
    fireEvent.change(input, { target: { value: "nope" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(
      await screen.findByText(/0 of 1 scope match the tag filter/),
    ).toBeTruthy();
    expect(screen.queryByText(/No scopes on this server/)).toBeNull();
    expect(screen.queryByText(/0 scopes on this group/)).toBeNull();
    const opts = screen.getAllByRole("option").map((o) => o.textContent);
    expect(opts.join("|")).not.toContain("10.31.1.0/24");
    expect(opts.join("|")).toContain("10.31.2.0/24");
  });
});
