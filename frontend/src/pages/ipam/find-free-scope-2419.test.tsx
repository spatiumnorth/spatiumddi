/**
 * @vitest-environment jsdom
 *
 * Find Free opened from a block says it searches that block, not the space
 * (#2419).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { IPSpace } from "@/lib/api";

const findFreeSpace = vi.hoisted(() =>
  vi.fn((_spaceId: string, _req: unknown) =>
    Promise.resolve<{ candidates: unknown[]; summary: object }>({
      candidates: [],
      summary: {},
    }),
  ),
);

vi.mock("@/lib/api", () => ({
  formatApiError: (e: unknown) => String(e),
  ipamApi: { findFreeSpace },
}));

const { FindFreeModal } = await import("./SubnetOpsModals");

afterEach(() => {
  cleanup();
  findFreeSpace.mockClear();
});

const SPACE = { id: "space-1", name: "campus" } as IPSpace;

function open(props: {
  defaultBlockId?: string;
  defaultBlockLabel?: string;
  defaultBlockCidr?: string;
}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <FindFreeModal space={SPACE} onClose={() => {}} {...props} />
    </QueryClientProvider>,
  );
}

describe("Find Free scope wording (#2419)", () => {
  it("from a block: names the block, says this block, never this space", async () => {
    open({ defaultBlockId: "blk-1", defaultBlockLabel: "10.222.0.0/20" });
    expect(screen.getByRole("dialog").textContent).toContain(
      "Find free space in block 10.222.0.0/20",
    );
    expect(screen.getByText(/unused CIDRs in this block/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Find" }));
    expect(
      await screen.findByText(/No free CIDRs of \/24 found in this block/),
    ).toBeTruthy();
    expect(document.body.textContent).not.toContain("this space");
    expect(document.body.textContent).not.toContain("campus");
  });

  it("from the space: still the space's name and 'this space'", async () => {
    open({});
    expect(screen.getByRole("dialog").textContent).toContain(
      "Find free space in campus",
    );
    expect(screen.getByText(/unused CIDRs in this space/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Find" }));
    expect(
      await screen.findByText(/No free CIDRs of \/24 found in this space/),
    ).toBeTruthy();
  });

  it("from an IPv6 block: starts on IPv6 with a prefix the block holds (#3324)", async () => {
    open({
      defaultBlockId: "blk-2",
      defaultBlockLabel: "fd33:236:0:300::/56",
      defaultBlockCidr: "fd33:236:0:300::/56",
    });
    const family = screen.getByRole("combobox") as HTMLSelectElement;
    expect(family.value).toBe("6");
    expect(screen.getByDisplayValue("64")).toBeTruthy();
  });

  it("an empty answer names the family it searched (#3324)", async () => {
    open({
      defaultBlockId: "blk-2",
      defaultBlockLabel: "fd33:236:0:300::/56",
      defaultBlockCidr: "fd33:236:0:300::/56",
    });
    fireEvent.click(screen.getByRole("button", { name: "Find" }));
    expect(await screen.findByText(/\(IPv6\)/)).toBeTruthy();
  });

  it("from an IPv4 block: still opens on IPv4 /24 (#3324)", () => {
    open({
      defaultBlockId: "blk-1",
      defaultBlockLabel: "10.222.0.0/24",
      defaultBlockCidr: "10.222.0.0/24",
    });
    const family = screen.getByRole("combobox") as HTMLSelectElement;
    expect(family.value).toBe("4");
    expect(screen.getByDisplayValue("24")).toBeTruthy();
  });

  it("from an IPv6 /127 block: IPv6, held to the /126 the server accepts (#3324)", () => {
    open({
      defaultBlockId: "blk-3",
      defaultBlockCidr: "fd33:236:0:300::/127",
    });
    expect((screen.getByRole("combobox") as HTMLSelectElement).value).toBe("6");
    expect(screen.getByDisplayValue("126")).toBeTruthy();
  });

  it("Find untouched from an IPv6 block sends an IPv6 /64 search (#3324)", async () => {
    open({
      defaultBlockId: "blk-2",
      defaultBlockCidr: "fd33:236:0:300::/56",
    });
    fireEvent.click(screen.getByRole("button", { name: "Find" }));
    await screen.findByText(/No free CIDRs/);
    expect(findFreeSpace).toHaveBeenCalledWith(
      "space-1",
      expect.objectContaining({ address_family: 6, prefix_length: 64 }),
    );
  });

  it("prints a /64's free addresses exactly, never the int64 cap (#3322)", async () => {
    findFreeSpace.mockImplementationOnce(() =>
      Promise.resolve({
        candidates: [
          {
            cidr: "fd33:236:0:300::/64",
            parent_block_id: "blk-2",
            parent_block_cidr: "fd33:236:0:300::/56",
            free_addresses: 2 ** 63,
            free_addresses_exact: "18446744073709551616",
          },
        ],
        summary: {},
      }),
    );
    open({ defaultBlockId: "blk-2", defaultBlockCidr: "fd33:236:0:300::/56" });
    fireEvent.click(screen.getByRole("button", { name: "Find" }));
    const cell = await screen.findByText(/18.446.744.073.709.551.616/);
    expect(cell.textContent?.replace(/\D/g, "")).toBe("18446744073709551616");
    expect(document.body.textContent).not.toMatch(/9.?223.?372/);
  });
});
