/**
 * @vitest-environment jsdom
 *
 * A subnet's address rows offer Edit and Delete only to a user who may write
 * the address (#2520).
 *
 * #1175 gated the IPAM header and the row's checkbox, but the row's own Edit
 * and Delete icons were rendered for every non-read-only address, so a
 * read-only Viewer opened Edit and was refused on Save. Real
 * `usePermissions`, answered from `GET /auth/me/permissions`.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { Subnet } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const stubs = Object.fromEntries(
    Object.entries(actual)
      .filter(([name, v]) => name.endsWith("Api") && typeof v === "object")
      .map(([name]) => [
        name,
        new Proxy(
          {},
          {
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : (...args: unknown[]) =>
                    (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    modules: [],
    ready: true,
    isLoading: false,
    isError: false,
    refetch: () => {},
    enabled: () => true,
  }),
}));

const { SubnetDetail } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const STAMP = "2026-10-22T00:00:00Z";

function signInAs(grants: [string, string][] | "superadmin") {
  answers.authApi = {
    myPermissions: () =>
      Promise.resolve(
        grants === "superadmin"
          ? { is_superadmin: true, grants: [] }
          : {
              is_superadmin: false,
              grants: grants.map(([action, resource_type]) => ({
                action,
                resource_type,
                resource_id: null,
              })),
            },
      ),
  };
}

async function openSubnet() {
  answers.ipamApi = {
    listAddresses: () =>
      Promise.resolve([
        {
          id: "a",
          subnet_id: "sub-1",
          address: "10.1.0.5",
          status: "allocated",
          role: null,
          hostname: "h-a",
          fqdn: null,
          description: "",
          mac_address: null,
          tags: {},
          custom_fields: {},
          created_at: STAMP,
          modified_at: STAMP,
        },
      ]),
  };
  answers.dhcpApi = { listScopesBySubnet: () => Promise.resolve([]) };
  const subnet = {
    id: "sub-1",
    space_id: "sp-1",
    block_id: "blk-1",
    network: "10.1.0.0/24",
    name: "lab",
    total_ips: 254,
    allocated_ips: 1,
    utilization_percent: 1,
    dns_group_ids: [],
  } as unknown as Subnet;
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <SubnetDetail subnet={subnet} onSubnetEdited={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByText("h-a");
  // Let the permission answer land: every gate is closed while it loads.
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
}

describe("a subnet's address row (#2520)", () => {
  it("offers a read-only Viewer neither Edit nor Delete", async () => {
    signInAs([["read", "*"]]);
    await openSubnet();
    expect(screen.queryByRole("button", { name: "Edit 10.1.0.5" })).toBeNull();
    expect(
      screen.queryByRole("button", { name: "Delete 10.1.0.5" }),
    ).toBeNull();
  });

  it("offers a superadmin both", async () => {
    signInAs("superadmin");
    await openSubnet();
    expect(screen.getByRole("button", { name: "Edit 10.1.0.5" })).toBeTruthy();
    expect(
      screen.getByRole("button", { name: "Delete 10.1.0.5" }),
    ).toBeTruthy();
  });

  it("offers an operator who may write subnets both", async () => {
    signInAs([
      ["read", "*"],
      ["write", "subnet"],
    ]);
    await openSubnet();
    expect(screen.getByRole("button", { name: "Edit 10.1.0.5" })).toBeTruthy();
    expect(
      screen.getByRole("button", { name: "Delete 10.1.0.5" }),
    ).toBeTruthy();
  });
});
