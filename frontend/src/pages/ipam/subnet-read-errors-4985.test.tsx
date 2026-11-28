/**
 * @vitest-environment jsdom
 *
 * #4985: a failed address-list / Next available / available-subnets read is
 * said, not drawn as an empty or full subnet. A real empty answer still says
 * so.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import type { Subnet } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}
const fails = () => Promise.reject(new Error("network down"));

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

const { SubnetDetail, OrphansModal, AddAddressModal, CreateSubnetModal } =
  await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function open(ui: ReactNode) {
  answer("authApi", "myPermissions", () =>
    Promise.resolve({ is_superadmin: true, grants: [] }),
  );
  answer("dhcpApi", "listScopesBySubnet", () => Promise.resolve([]));
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const subnet = {
  id: "sub-1",
  space_id: "sp-1",
  block_id: "blk-1",
  network: "10.1.0.0/24",
  name: "lab",
  total_ips: 254,
  allocated_ips: 2,
  utilization_percent: 1,
  dns_group_ids: [],
} as unknown as Subnet;

const detail = () =>
  open(<SubnetDetail subnet={subnet} onSubnetEdited={() => {}} />);

describe("subnet address table (#4985)", () => {
  it("says the read failed, not that nothing is allocated", async () => {
    answer("ipamApi", "listAddresses", fails);
    detail();
    expect(await screen.findByText(/Couldn't load/)).toBeTruthy();
    expect(screen.queryByText("No IP addresses allocated yet.")).toBeNull();
    expect(screen.queryByText("Allocate first IP")).toBeNull();
  });

  it("a real empty list still says so", async () => {
    answer("ipamApi", "listAddresses", () => Promise.resolve([]));
    detail();
    expect(
      await screen.findByText("No IP addresses allocated yet."),
    ).toBeTruthy();
  });
});

describe("Clean Orphans (#4985)", () => {
  it("says the read failed, not that there are no orphans", async () => {
    answer("ipamApi", "listAddresses", fails);
    open(
      <OrphansModal subnetId="sub-1" subnetLabel="lab" onClose={() => {}} />,
    );
    expect(await screen.findByText(/Couldn't load/)).toBeTruthy();
    expect(screen.queryByText("No orphans in this subnet.")).toBeNull();
  });

  it("a real empty list still says so", async () => {
    answer("ipamApi", "listAddresses", () => Promise.resolve([]));
    open(
      <OrphansModal subnetId="sub-1" subnetLabel="lab" onClose={() => {}} />,
    );
    expect(await screen.findByText("No orphans in this subnet.")).toBeTruthy();
  });
});

describe("Allocate IP Next available (#4985)", () => {
  const modal = () =>
    open(<AddAddressModal subnetId="sub-1" onClose={() => {}} />);

  it("says the read failed, not that no IP is free", async () => {
    answer("ipamApi", "previewNextIp", fails);
    modal();
    expect(await screen.findByText(/Couldn't load/)).toBeTruthy();
    expect(screen.queryByText(/No free IPs in this subnet/)).toBeNull();
  });

  it("a real exhausted subnet still says so", async () => {
    answer("ipamApi", "previewNextIp", () =>
      Promise.resolve({ address: null, strategy: "sequential" }),
    );
    modal();
    expect(await screen.findByText(/No free IPs in this subnet/)).toBeTruthy();
  });
});

describe("New Subnet Find by size (#4985)", () => {
  const modal = () => {
    answer("ipamApi", "listBlocks", () =>
      Promise.resolve([{ id: "blk-1", network: "10.0.0.0/16", name: "" }]),
    );
    open(
      <CreateSubnetModal
        spaceId="sp-1"
        defaultBlockId="blk-1"
        onClose={() => {}}
      />,
    );
    fireEvent.click(screen.getByText("Find by size"));
  };

  it("says the read failed, not that no subnet is available", async () => {
    answer("ipamApi", "availableSubnets", fails);
    modal();
    expect(await screen.findByText(/Couldn't load/)).toBeTruthy();
    expect(screen.queryByText(/No available \/24 subnets/)).toBeNull();
  });

  it("a real empty answer still says so", async () => {
    answer("ipamApi", "availableSubnets", () => Promise.resolve([]));
    modal();
    expect(await screen.findByText(/No available \/24 subnets/)).toBeTruthy();
  });
});
