/**
 * @vitest-environment jsdom
 *
 * Free-range rows ("N free · click to allocate") in the IP table (#2137).
 *
 * Two allocated addresses with a hole between them draw one gap row; the
 * tests hold whether it is drawn against the subnet's size, ownership, its
 * explicit setting and the session toggle.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { IPAddress, Subnet } from "@/lib/api";
import {
  defaultShowFreeRanges,
  resolveShowFreeRanges,
} from "@/lib/ipam-free-ranges";

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

beforeEach(() => {
  sessionStorage.clear();
});
afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const STAMP = "2026-10-18T00:00:00Z";

function addr(id: string, address: string): IPAddress {
  return {
    id,
    subnet_id: "sub-1",
    address,
    status: "allocated",
    role: null,
    hostname: `h-${id}`,
    fqdn: null,
    description: "",
    mac_address: null,
    tags: {},
    custom_fields: {},
    created_at: STAMP,
    modified_at: STAMP,
  } as IPAddress;
}

function show(network: string, over: Partial<Subnet> = {}, base = "10.1.0") {
  answer("ipamApi", "listAddresses", () =>
    Promise.resolve([addr("a", `${base}.1`), addr("b", `${base}.200`)]),
  );
  answer("dhcpApi", "listScopesBySubnet", () => Promise.resolve([]));
  const subnet = {
    id: "sub-1",
    space_id: "sp-1",
    block_id: "blk-1",
    network,
    name: "lab",
    total_ips: 254,
    allocated_ips: 2,
    utilization_percent: 1,
    dns_group_ids: [],
    ...over,
  } as unknown as Subnet;
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <SubnetDetail subnet={subnet} onSubnetEdited={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

const gap = () => screen.queryByText(/click to allocate/);
const toggle = () =>
  screen.getByLabelText("Hide free ranges") as HTMLInputElement;

describe("free-range rows", () => {
  it("shows the gap row on a small subnet by default", async () => {
    show("10.1.0.0/24");
    await screen.findByText("h-a");
    expect(gap()).not.toBeNull();
    expect(toggle().checked).toBe(false);
  });

  it("hides it on a subnet larger than a /16, toggle reads checked", async () => {
    show("10.0.0.0/8", {}, "10.0.0");
    await screen.findByText("h-a");
    expect(gap()).toBeNull();
    expect(toggle().checked).toBe(true);
  });

  it("keeps a /16 itself on the default-on side of the threshold", async () => {
    show("10.1.0.0/16");
    await screen.findByText("h-a");
    expect(gap()).not.toBeNull();
  });

  it("hides it on an integration-owned subnet", async () => {
    show("10.1.0.0/24", { integration_owner: "tailscale" });
    await screen.findByText("h-a");
    expect(gap()).toBeNull();
  });

  it("an explicit show overrides the integration default", async () => {
    show("10.1.0.0/24", {
      integration_owner: "tailscale",
      show_free_ranges: true,
    });
    await screen.findByText("h-a");
    expect(gap()).not.toBeNull();
  });

  it("an explicit hide overrides the small-subnet default", async () => {
    show("10.1.0.0/24", { show_free_ranges: false });
    await screen.findByText("h-a");
    expect(gap()).toBeNull();
  });

  it("the session toggle flips it both ways and is remembered", async () => {
    show("10.1.0.0/24");
    await screen.findByText("h-a");
    fireEvent.click(toggle());
    await waitFor(() => expect(gap()).toBeNull());
    expect(sessionStorage.getItem("ipam-hide-free-ranges")).toContain(
      '"sub-1":true',
    );
    fireEvent.click(toggle());
    await waitFor(() => expect(gap()).not.toBeNull());
  });

  it("the toggle can reveal rows on a default-hidden subnet", async () => {
    show("10.0.0.0/8", {}, "10.0.0");
    await screen.findByText("h-a");
    fireEvent.click(toggle());
    await waitFor(() => expect(gap()).not.toBeNull());
  });

  it("leaves the header summary and Allocate IP alone while hidden", async () => {
    show("10.1.0.0/24", { show_free_ranges: false });
    await screen.findByText("h-a");
    expect(screen.getAllByText(/Allocate IP/).length).toBeGreaterThan(0);
  });
});

describe("default rule", () => {
  it("covers v4 size, v6 size, ownership and explicit values", () => {
    expect(defaultShowFreeRanges({ network: "10.0.0.0/16" })).toBe(true);
    expect(defaultShowFreeRanges({ network: "10.0.0.0/15" })).toBe(false);
    expect(defaultShowFreeRanges({ network: "2001:db8::/64" })).toBe(true);
    expect(defaultShowFreeRanges({ network: "2001:db8::/32" })).toBe(false);
    expect(
      defaultShowFreeRanges({ network: "10.0.0.0/24", integration_owner: "k" }),
    ).toBe(false);
    expect(
      resolveShowFreeRanges({ network: "10.0.0.0/8", show_free_ranges: true }),
    ).toBe(true);
    expect(
      resolveShowFreeRanges({ network: "10.0.0.0/24", show_free_ranges: null }),
    ).toBe(true);
  });
});
