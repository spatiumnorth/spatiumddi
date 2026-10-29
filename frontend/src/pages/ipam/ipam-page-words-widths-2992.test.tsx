/**
 * @vitest-environment jsdom
 *
 * IPAM page words and widths (#2992, #2993, #2994).
 *
 * - a refused Clean Orphans purge says why (#2992);
 * - a subnet row keeps its CIDR whole and cuts the name (#2993);
 * - a quick-filter that matches nothing reports every space as hidden (#2994).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import { DndContext } from "@dnd-kit/core";
import type { IPAddress, IPBlock, IPSpace, Subnet } from "@/lib/api";

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
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { OrphansModal, SubnetRow, SpaceSection } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function open(ui: ReactNode) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <DndContext>{ui}</DndContext>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Clean Orphans on a refused purge (#2992)", () => {
  const orphan = {
    id: "a-1",
    address: "10.174.112.70",
    status: "orphan",
  } as unknown as IPAddress;

  function setup(purge: Answer) {
    answers.ipamApi = {
      listAddresses: () => Promise.resolve([orphan]),
      purgeOrphans: purge,
    };
    open(
      <OrphansModal
        subnetId="sn-1"
        subnetLabel="10.174.112.64/26"
        onClose={() => {}}
      />,
    );
  }

  it("shows the server's reason and keeps the dialog", async () => {
    const purge = vi.fn(() =>
      Promise.reject({
        response: { status: 404, data: { detail: "Subnet not found" } },
      }),
    );
    setup(purge);
    fireEvent.click(await screen.findByText("10.174.112.70"));
    fireEvent.click(screen.getByRole("button", { name: "Purge 1" }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Subnet not found");
    expect(screen.getByText("10.174.112.70")).toBeTruthy();
  });

  it("shows no alert before a refusal", async () => {
    setup(vi.fn());
    await screen.findByText("10.174.112.70");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("clears the reason when the purge is tried again", async () => {
    let calls = 0;
    setup(() => {
      calls += 1;
      return calls === 1
        ? Promise.reject({
            response: { status: 502, data: { detail: "DHCP write failed" } },
          })
        : new Promise(() => {});
    });
    fireEvent.click(await screen.findByText("10.174.112.70"));
    fireEvent.click(screen.getByRole("button", { name: "Purge 1" }));
    await screen.findByRole("alert");
    fireEvent.click(screen.getByRole("button", { name: "Purge 1" }));
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
  });
});

describe("SubnetRow CIDR width (#2993)", () => {
  it("never shrinks the CIDR and truncates the name instead", () => {
    const subnet = {
      id: "sn-1",
      space_id: "sp-1",
      block_id: "b-1",
      network: "10.233.101.0/24",
      name: "a-very-long-subnet-name-that-would-squeeze-the-cidr",
      customer_id: "c-1",
      site_id: null,
      utilization_percent: 0,
      total_ips: 254,
    } as unknown as Subnet;
    open(
      <SubnetRow
        subnet={subnet}
        isSelected={false}
        onSelect={() => {}}
        onDelete={() => {}}
        onEdited={() => {}}
      />,
    );
    const cidr = screen.getAllByText("10.233.101.0/24")[0];
    expect(cidr.className).toContain("shrink-0");
    expect(cidr.className).toContain("whitespace-nowrap");
    expect(cidr.className).not.toMatch(/\bflex-1\b|\btruncate\b/);
    const name = screen.getByText(subnet.name as string);
    expect(name.className).toContain("min-w-0");
    expect(name.className).toContain("truncate");
  });
});

describe("tree quick-filter that matches nothing (#2994)", () => {
  const space = { id: "sp-1", name: "lab", description: "" } as IPSpace;
  const block = {
    id: "b-1",
    space_id: "sp-1",
    parent_block_id: null,
    network: "10.73.0.0/16",
    name: "",
  } as IPBlock;
  const subnet = {
    id: "sn-1",
    space_id: "sp-1",
    block_id: "b-1",
    network: "10.73.5.0/24",
    name: "",
    utilization_percent: 0,
    total_ips: 254,
  } as Subnet;

  function render_(filter: string, onHidden: (id: string, h: boolean) => void) {
    answers.ipamApi = {
      listSubnets: () => Promise.resolve([subnet]),
      listBlocks: () => Promise.resolve([block]),
    };
    open(
      <SpaceSection
        space={space}
        selectedSubnetId={null}
        selectedBlockId={null}
        isSpaceSelected={false}
        onSelectSpace={() => {}}
        onSelectSubnet={() => {}}
        onSelectBlock={() => {}}
        filter={filter}
        onHiddenChange={onHidden}
      />,
    );
  }

  it("reports the space hidden once its reads answered", async () => {
    const onHidden = vi.fn();
    render_("zzz-no-such-thing", onHidden);
    await waitFor(() => expect(onHidden).toHaveBeenCalledWith("sp-1", true));
  });

  it("does not report hidden while the reads are pending or on a hit", async () => {
    const onHidden = vi.fn();
    render_("10.73.5", onHidden);
    await screen.findByText("10.73.5.0/24");
    expect(onHidden).not.toHaveBeenCalledWith("sp-1", true);
  });
});
