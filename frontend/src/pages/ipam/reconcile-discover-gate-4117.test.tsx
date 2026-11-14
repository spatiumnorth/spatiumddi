/**
 * @vitest-environment jsdom
 *
 * A subnet's Reconcile report is a read, but its "Discover now" queues a
 * sweep, which the server takes write on subnets for. A read-only user sees
 * it disabled with the permission it needs, and a refused press says why
 * instead of "Failed to queue the sweep." (#4117). Real `usePermissions`.
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
import type { ReactNode } from "react";
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

// Module ids switched off for the current case; everything else is on.
const modulesOff = new Set<string>();

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    modules: [],
    ready: true,
    isLoading: false,
    isError: false,
    refetch: () => {},
    enabled: (id: string) => !modulesOff.has(id),
  }),
}));

const { SubnetDetail } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  modulesOff.clear();
  for (const name of Object.keys(answers)) delete answers[name];
});

const STAMP = "2026-10-22T00:00:00Z";

type Grants = [string, string][] | "superadmin" | "loading";

// Resolves once the permission set has been served, so a "disabled" verdict
// is the gate's answer and not just the fail-closed loading state.
let served: Promise<void> = Promise.resolve();

function signInAs(grants: Grants) {
  let markServed = () => {};
  served = new Promise((r) => (markServed = r));
  answers.authApi = {
    myPermissions: () => {
      if (grants === "loading") return new Promise(() => {});
      markServed();
      return Promise.resolve(
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
      );
    },
  };
}

const VIEWER: [string, string][] = [
  ["read", "ip_space"],
  ["read", "ip_block"],
  ["read", "subnet"],
  ["read", "ip_address"],
];
const WRITER: [string, string][] = [...VIEWER, ["write", "subnet"]];

async function mount(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 80));
  });
}

const SUBNET = {
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

async function openReport(grants: Grants) {
  signInAs(grants);
  answers.ipamApi = {
    listAddresses: () => Promise.resolve([]),
    getReconciliation: () =>
      Promise.resolve({
        last_discovery_at: null,
        counts: {
          in_ipam_not_seen: 0,
          discovered_not_allocated: 0,
          status_mismatch: 0,
        },
        in_ipam_not_seen: [],
        discovered_not_allocated: [],
        status_mismatch: [],
      }),
    triggerDiscovery: () =>
      Promise.reject(
        Object.assign(new Error("403"), {
          response: {
            status: 403,
            data: { detail: "Permission denied: need 'write' on 'subnet'" },
          },
        }),
      ),
  };
  await mount(<SubnetDetail subnet={SUBNET} onSubnetEdited={() => {}} />);
  await served;
  fireEvent.click(screen.getByRole("button", { name: /Tools/ }));
  const item = await screen.findByText("Reconcile (IP discovery)");
  fireEvent.click(item.closest("button") as HTMLButtonElement);
  return (await screen.findByRole("button", {
    name: /Discover now/,
  })) as HTMLButtonElement;
}

describe("Reconcile > Discover now (#4117)", () => {
  it("is disabled, with the permission it needs, for a read-only user", async () => {
    const btn = await openReport(VIEWER);
    await waitFor(() => expect(btn.disabled).toBe(true));
    expect(btn.title).toMatch(/write permission on subnets/);
  });

  it("is enabled for a user who can write subnets", async () => {
    const btn = await openReport(WRITER);
    expect(btn.disabled).toBe(false);
  });

  it("says why a refused sweep was refused", async () => {
    const btn = await openReport(WRITER);
    fireEvent.click(btn);
    expect(
      await screen.findByText(/Permission denied: need 'write' on 'subnet'/),
    ).toBeTruthy();
    expect(screen.queryByText("Failed to queue the sweep.")).toBeNull();
  });
});
