/**
 * @vitest-environment jsdom
 *
 * #2447 — the Static Assignments tab's "Add to scope" picker tells
 * same-named scopes apart by their subnet.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const scope = (id: string, subnet_id: string) => ({
    id,
    name: "default",
    subnet_id,
    group_id: "g1",
    address_family: "ipv4",
  });
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
    },
    ipamApi: {
      ...actual.ipamApi,
      listSubnets: () =>
        Promise.resolve([
          { id: "n1", network: "10.243.1.0/24" },
          { id: "n2", network: "10.243.2.0/24" },
        ]),
    },
    dhcpApi: {
      ...actual.dhcpApi,
      listScopesByGroup: () =>
        Promise.resolve([scope("s1", "n1"), scope("s2", "n2")]),
      listStatics: () => Promise.resolve([]),
      listPools: () => Promise.resolve([]),
      listGroups: () => Promise.resolve([]),
      scopePoolOccupancy: () => Promise.resolve([]),
    },
  };
});

import { ServerPoolsOrStaticsTab } from "./DHCPPage";

afterEach(cleanup);

describe("Add to scope picker", () => {
  it("gives same-named scopes distinct options", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <ServerPoolsOrStaticsTab groupId="g1" kind="statics" />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const opt = await screen.findByRole("option", {
      name: "default (10.243.1.0/24)",
    });
    expect(opt).toBeTruthy();
    const texts = screen.getAllByRole("option").map((o) => o.textContent);
    expect(new Set(texts).size).toBe(texts.length);
    expect(texts).toContain("default (10.243.2.0/24)");
  });
});
