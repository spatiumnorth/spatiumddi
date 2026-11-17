/**
 * @vitest-environment jsdom
 *
 * With the Address sets module off the subnet shows no Address Sets tab and
 * asks for no list (#3762): that route answers 404 while the module is off.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render } from "@testing-library/react";
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

const off = vi.hoisted(() => new Set<string>());

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    modules: [],
    ready: true,
    isLoading: false,
    isError: false,
    refetch: () => {},
    enabled: (id: string) => !off.has(id),
  }),
}));

const { SubnetDetail } = await import("./IPAMPage");

vi.setConfig({ testTimeout: 30_000 });

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver;

afterEach(() => {
  cleanup();
  off.clear();
  for (const name of Object.keys(answers)) delete answers[name];
});

const settle = () =>
  act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });

const subnet = {
  id: "sub-1",
  space_id: "sp-1",
  block_id: "blk-1",
  network: "10.142.1.0/24",
  name: "sn1",
  total_ips: 254,
  allocated_ips: 1,
  utilization_percent: 1,
  dns_group_ids: [],
  customer_id: null,
  site_id: null,
} as unknown as Subnet;

const wrap = (ui: React.ReactNode) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
};

async function open() {
  answers.authApi = {
    myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
  };
  const list = vi.fn(() => Promise.resolve([]));
  answers.addressSetsApi = { list };
  answers.ipamApi = { listAddresses: () => Promise.resolve([]) };
  answers.dhcpApi = { listScopesBySubnet: () => Promise.resolve([]) };
  wrap(<SubnetDetail subnet={subnet} onSubnetEdited={() => {}} />);
  await settle();
  return list;
}

const tab = () =>
  Array.from(document.querySelectorAll("button")).find(
    (b) => b.textContent?.trim() === "Address Sets",
  );

describe("the Address Sets tab follows its module (#3762)", () => {
  it("is offered, and its list asked for, while the module is on", async () => {
    const list = await open();
    expect(tab()).toBeTruthy();
    expect(list).toHaveBeenCalled();
  });

  it("is hidden and its list not requested while the module is off", async () => {
    off.add("ipam.address_sets");
    const list = await open();
    expect(tab()).toBeUndefined();
    expect(list).not.toHaveBeenCalled();
  });
});
