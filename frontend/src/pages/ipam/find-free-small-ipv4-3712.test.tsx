/**
 * @vitest-environment jsdom
 *
 * Find Free from an IPv4 block longer than /24 starts on a size the block can
 * hold, and an empty answer says when the size is the reason (#3712).
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
import type { IPSpace } from "@/lib/api";

const findFreeSpace = vi.fn((..._a: unknown[]) =>
  Promise.resolve({ candidates: [], summary: {} }),
);
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, ipamApi: { ...actual.ipamApi, findFreeSpace } };
});

const { FindFreeModal } = await import("./SubnetOpsModals");

afterEach(() => {
  cleanup();
  findFreeSpace.mockClear();
});

async function open(blockCidr: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <FindFreeModal
          space={{ id: "sp-1", name: "lab" } as unknown as IPSpace}
          onClose={() => {}}
          defaultBlockId="blk"
          defaultBlockLabel={blockCidr}
          defaultBlockCidr={blockCidr}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(await screen.findByRole("button", { name: "Find" }));
  await waitFor(() => expect(findFreeSpace).toHaveBeenCalledTimes(1));
  return findFreeSpace.mock.calls[0][1] as {
    prefix_length: number;
    address_family: number;
  };
}

describe("Find Free from a small IPv4 block (#3712)", () => {
  it.each([
    ["10.109.64.0/26", 27],
    ["10.0.0.0/25", 26],
    ["10.0.0.0/29", 30],
    ["10.0.0.0/32", 30],
    // PR #3331's /24 stands for a /24 and shorter.
    ["10.0.0.0/24", 24],
    ["10.0.0.0/16", 24],
  ])("%s starts on /%i", async (cidr, prefix) => {
    const req = await open(cidr);
    expect(req.address_family).toBe(4);
    expect(req.prefix_length).toBe(prefix);
  });

  it("an empty answer names the block being smaller than the size", async () => {
    await open("10.0.0.0/32");
    expect(
      await screen.findByText(/smaller than a \/30, so nothing of that size/),
    ).toBeTruthy();
  });

  it("no such note when the block can hold the size", async () => {
    await open("10.0.0.0/26");
    await screen.findByText(/No free CIDRs of \/27/);
    expect(screen.queryByText(/so nothing of that size/)).toBeNull();
  });
});
