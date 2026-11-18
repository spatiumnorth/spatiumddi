/**
 * @vitest-environment jsdom
 *
 * IPAM: the free-range rows, the empty state's Allocate first IP and the
 * Imported chip's remove are not offered to a user who may not write (#3883).
 * The API objects are replaced by recorders; the permission hook is real,
 * fed by ``authApi.myPermissions``.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import type { IPAddress, Subnet } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
/** Every ``<api>.<method>`` call made, in order. */
const calls: string[] = [];

const mods = { ready: true, off: new Set<string>() };

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
                : (...args: unknown[]) => {
                    calls.push(`${name}.${method}`);
                    return (answers[name]?.[method] ?? pending)(...args);
                  },
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    modules: [],
    ready: mods.ready,
    isLoading: !mods.ready,
    isError: false,
    refetch: () => {},
    enabled: (id: string) => !mods.off.has(id),
  }),
}));

const { ImportedChip, SubnetDetail } = await import("./ipam/IPAMPage");

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

beforeEach(() => {
  mods.ready = true;
  mods.off = new Set();
  calls.length = 0;
  localStorage.clear();
  sessionStorage.clear();
});

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const STAMP = "2026-10-02T00:00:00Z";
const address = (over: Partial<IPAddress> = {}): IPAddress =>
  ({
    id: "ip-1",
    subnet_id: "sub-1",
    address: "10.85.20.1",
    status: "allocated",
    role: null,
    hostname: "web01",
    fqdn: null,
    description: "",
    mac_address: null,
    tags: {},
    custom_fields: {},
    created_at: STAMP,
    modified_at: STAMP,
    ...over,
  }) as IPAddress;

function open(ui: ReactNode, qc?: QueryClient) {
  const client =
    qc ?? new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const r = render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
  return { client, ...r };
}

describe("Writes offered to a read-only user (#3883)", () => {
  const subnet = {
    id: "sub-1",
    space_id: "sp-1",
    block_id: "blk-1",
    network: "10.85.20.0/24",
    name: "lab",
    total_ips: 254,
    allocated_ips: 2,
    utilization_percent: 1,
  } as unknown as Subnet;

  function detail(superadmin: boolean, rows: IPAddress[]) {
    answer("authApi", "myPermissions", () =>
      Promise.resolve({ is_superadmin: superadmin, grants: [] }),
    );
    answer("ipamApi", "listAddresses", () => Promise.resolve(rows));
    answer("dhcpApi", "listScopesBySubnet", () => Promise.resolve([]));
    open(<SubnetDetail subnet={subnet} onSubnetEdited={() => {}} />);
  }

  it("offers Allocate first IP to a writer (control) and disables it for a reader", async () => {
    detail(true, []);
    const btn = await screen.findByRole("button", {
      name: /Allocate first IP/,
    });
    await waitFor(() =>
      expect((btn as HTMLButtonElement).disabled).toBe(false),
    );
    cleanup();
    detail(false, []);
    const ro = await screen.findByRole("button", { name: /Allocate first IP/ });
    expect((ro as HTMLButtonElement).disabled).toBe(true);
  });

  it("draws 'click to allocate' on a free range for a writer, not for a reader", async () => {
    const rows = [
      address({ id: "a", address: "10.85.20.1" }),
      address({ id: "b", address: "10.85.20.20" }),
    ];
    detail(true, rows);
    expect(await screen.findAllByText(/click to allocate/)).toBeTruthy();
    cleanup();
    detail(false, rows);
    await screen.findAllByText("10.85.20.20");
    expect(screen.queryByText(/click to allocate/)).toBeNull();
  });

  it("disables the Imported chip's remove for a reader, not for a writer", () => {
    const chip = (writable: boolean) => (
      <ImportedChip
        fields={{ import_source: "netbox" }}
        kind="subnet"
        id="sub-1"
        writable={writable}
        onUpdated={() => {}}
      />
    );
    const a = open(chip(true));
    const x = () =>
      screen.getByRole("button", {
        name: "Remove import metadata from this subnet",
      }) as HTMLButtonElement;
    expect(x().disabled).toBe(false);
    a.unmount();
    open(chip(false));
    expect(x().disabled).toBe(true);
  });
});
