/**
 * @vitest-environment jsdom
 *
 * A subnet page offers Sync > DNS and the Edit dialog's Delete only to a
 * holder the server would let through (#2571). Both routes ask at the TYPE
 * level; a grant scoped to one subnet reaches neither. Real `usePermissions`.
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

type G = [string, string, string | null];

function signInAs(grants: G[] | "superadmin") {
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
  answers.dhcpApi = { listScopesBySubnet: () => Promise.resolve([]) };
  const subnet = {
    id: "sub-1",
    space_id: "sp-1",
    block_id: "blk-1",
    network: "10.1.0.0/24",
    name: "lab",
    total_ips: 254,
    allocated_ips: 0,
    utilization_percent: 0,
    dns_group_ids: [],
    created_at: STAMP,
    modified_at: STAMP,
  } as unknown as Subnet;
  // Edit Subnet reads the subnet fresh on open (#3269).
  answers.ipamApi = {
    listAddresses: () => Promise.resolve([]),
    getSubnet: () => Promise.resolve(subnet),
  };
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <SubnetDetail subnet={subnet} onSubnetEdited={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 80));
  });
}

async function dnsSyncItem() {
  fireEvent.click(screen.getByRole("button", { name: /Sync/ }));
  return (await screen.findByText("DNS")).closest("button") as HTMLElement;
}

async function deleteButton() {
  fireEvent.click(screen.getByRole("button", { name: "Edit" }));
  fireEvent.click(await screen.findByRole("button", { name: "Danger zone" }));
  return (await screen.findByText(/Delete this subnet/)).closest(
    "button",
  ) as HTMLButtonElement;
}

const SCOPED: G[] = [
  ["read", "subnet", "sub-1"],
  ["write", "subnet", "sub-1"],
];

describe("subnet page DNS sync and Delete gates (#2571)", () => {
  it("disables Sync > DNS for a holder scoped to this subnet", async () => {
    signInAs(SCOPED);
    await openSubnet();
    const item = await dnsSyncItem().catch(() => null);
    // Either the whole menu is disabled (nothing else in it) or the item is.
    if (item) expect((item as HTMLButtonElement).disabled).toBe(true);
    else
      expect(
        (screen.getByRole("button", { name: /Sync/ }) as HTMLButtonElement)
          .disabled,
      ).toBe(true);
  });

  it("disables Delete for a delete grant scoped to this subnet", async () => {
    // Write at the type level only so the Edit dialog opens on this base.
    signInAs([
      ["read", "*", null],
      ["write", "subnet", null],
      ["delete", "subnet", "sub-1"],
    ]);
    await openSubnet();
    const del = await deleteButton();
    expect(del.disabled).toBe(true);
    expect(del.title).toMatch(/delete permission on subnets/);
  });

  it("enables both for an operator with type-level rights", async () => {
    signInAs([
      ["read", "*", null],
      ["write", "subnet", null],
      ["delete", "subnet", null],
    ]);
    await openSubnet();
    expect(((await dnsSyncItem()) as HTMLButtonElement).disabled).toBe(false);
    fireEvent.keyDown(document, { key: "Escape" });
    expect((await deleteButton()).disabled).toBe(false);
  });

  it("keeps Delete disabled for write-without-delete", async () => {
    signInAs([
      ["read", "*", null],
      ["write", "subnet", null],
    ]);
    await openSubnet();
    expect((await deleteButton()).disabled).toBe(true);
  });

  it("enables both for a superadmin", async () => {
    signInAs("superadmin");
    await openSubnet();
    expect(((await dnsSyncItem()) as HTMLButtonElement).disabled).toBe(false);
    fireEvent.keyDown(document, { key: "Escape" });
    expect((await deleteButton()).disabled).toBe(false);
  });
});
