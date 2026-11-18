/**
 * @vitest-environment jsdom
 *
 * IPAM: a custom field the API stored as an object or a list reads as text on
 * the subnet page, never "[object Object]" (#4421). The API objects are
 * replaced by stubs.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { Subnet } from "@/lib/api";

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

const { SubnetDetail } = await import("./ipam/IPAMPage");

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

describe("Subnet header custom fields (#4421)", () => {
  it("shows an object as JSON text and a list joined", async () => {
    const subnet = {
      id: "sub-1",
      space_id: "sp-1",
      block_id: "blk-1",
      network: "10.25.1.0/24",
      name: "lab",
      total_ips: 254,
      allocated_ips: 0,
      utilization_percent: 0,
      custom_fields: {
        xp_plain: "plain-1",
        xp_obj: { k: "obj-1" },
        xp_list: ["list-a", "list-b"],
      },
    } as unknown as Subnet;
    answer("authApi", "myPermissions", () =>
      Promise.resolve({ is_superadmin: true, grants: [] }),
    );
    answer("ipamApi", "listAddresses", () => Promise.resolve([]));
    answer("dhcpApi", "listScopesBySubnet", () => Promise.resolve([]));
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <SubnetDetail subnet={subnet} onSubnetEdited={() => {}} />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(
      await screen.findByText("plain-1", {}, { timeout: 10000 }),
    ).toBeTruthy();
    expect(screen.getByText('{"k":"obj-1"}')).toBeTruthy();
    expect(screen.getByText("list-a, list-b")).toBeTruthy();
    expect(screen.queryByText(/\[object Object\]/)).toBeNull();
  }, 30000);
});
