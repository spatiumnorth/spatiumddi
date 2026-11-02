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

vi.mock("@/lib/api", () => ({
  formatApiError: (e: unknown) => String(e),
  ipamApi: {
    findFreeSpace: () => Promise.resolve({ candidates: [], summary: {} }),
  },
}));

const { FindFreeModal } = await import("./SubnetOpsModals");

afterEach(cleanup);

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
});
