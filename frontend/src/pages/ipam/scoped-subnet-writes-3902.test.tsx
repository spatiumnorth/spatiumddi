/**
 * @vitest-environment jsdom
 *
 * A holder whose grant names ONE subnet is offered only the address writes the
 * server admits to that grant (#3902): `PUT /subnets/{id}` and
 * `POST /subnets/{id}/addresses` (a specific IP). The next free address,
 * editing an existing address, bulk edit, bulk allocate and import want a
 * type-level write on subnets (or an address-set grant) and answer 403.
 * Real `usePermissions`.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
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

function signInAs(grants: [string, string, string | null][] | "superadmin") {
  answers.authApi = {
    myPermissions: () =>
      Promise.resolve(
        grants === "superadmin"
          ? { is_superadmin: true, grants: [] }
          : {
              is_superadmin: false,
              grants: grants.map(([action, resource_type, resource_id]) => ({
                action,
                resource_type,
                resource_id,
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

const SCOPED: [string, string, string | null][] = [
  ["read", "subnet", "sub-1"],
  ["write", "subnet", "sub-1"],
];

const button = (name: string) =>
  screen.getByRole("button", { name }) as HTMLButtonElement;

describe("a grant scoped to one subnet is not offered address writes the server refuses (#3902)", () => {
  it("opens Allocate IP in Specific IP, with Next available disabled and saying why", async () => {
    signInAs(SCOPED);
    await openSubnet();
    expect(button("Allocate IP").disabled).toBe(false);
    fireEvent.click(button("Allocate IP"));
    const next = await screen.findByRole("button", { name: "Next available" });
    expect((next as HTMLButtonElement).disabled).toBe(true);
    expect(next.title).toContain("Requires write permission on subnets");
    expect(
      (screen.getByRole("button", { name: "Specific IP" }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
    expect(screen.queryByText(/Finding next available IP/)).toBeNull();
  });

  it("offers no Edit button and no checkbox on a row", async () => {
    signInAs(SCOPED);
    await openSubnet();
    expect(screen.queryByRole("button", { name: "Edit 10.1.0.5" })).toBeNull();
    expect(screen.queryByRole("checkbox", { name: /10\.1\.0\.5/ })).toBeNull();
  });

  it("keeps Bulk allocate disabled with its reason", async () => {
    signInAs(SCOPED);
    await openSubnet();
    fireEvent.click(button("Tools"));
    const item = await screen.findByRole("menuitem", { name: /Bulk allocate/ });
    expect((item as HTMLButtonElement).disabled).toBe(true);
    expect(item.title).toContain("Requires write permission on subnets");
  });

  it("still offers a type-level writer Next available and the row Edit", async () => {
    signInAs([
      ["read", "*", null],
      ["write", "subnet", null],
    ]);
    await openSubnet();
    expect(button("Edit 10.1.0.5")).toBeTruthy();
    fireEvent.click(button("Allocate IP"));
    const next = await screen.findByRole("button", { name: "Next available" });
    expect((next as HTMLButtonElement).disabled).toBe(false);
  });
});
