/**
 * @vitest-environment jsdom
 *
 * An IPv6 block's Allocation map draws its children (#3707). The Band read
 * IPv4 only ("No allocation data"), and the Treemap clamped IPv6 weights so
 * a child filling half the block rounded to nothing.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { IPBlock } from "@/lib/api";
import { bigFraction, cidrSpan } from "@/lib/cidr";

// The API's `size` saturates for IPv6 (the real answer is an int cap).
const SAT = Number.MAX_SAFE_INTEGER;
const free = ["fd71:a7::/50", "fd71:a7:0:4000::/50"].map((network) => ({
  network,
  first: "",
  last: "",
  size: SAT,
  prefix_len: 50,
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    ipamApi: { ...actual.ipamApi, blockFreeSpace: async () => free },
  };
});

let treemapData: { network: string; size: number }[] = [];
vi.mock("recharts", () => ({
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  Tooltip: () => null,
  Treemap: ({ data }: { data: { network: string; size: number }[] }) => {
    treemapData = data;
    return null;
  },
}));

import { FreeSpaceBand } from "./FreeSpaceBand";
import { FreeSpaceTreemap } from "./FreeSpaceTreemap";

const block = { id: "b", network: "fd71:a7::/48" } as IPBlock;
const child = {
  id: "c",
  network: "fd71:a7:0:8000::/49",
  name: "half",
  utilization_percent: 10,
} as IPBlock;

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

afterEach(cleanup);

describe("IPv6 allocation map (#3707)", () => {
  it("the Band draws the child block and the free ranges", async () => {
    wrap(
      <FreeSpaceBand
        block={block}
        directSubnets={[]}
        childBlocks={[child]}
        onSelectFree={() => {}}
      />,
    );
    await waitFor(() =>
      expect(screen.getByLabelText(/fd71:a7:0:8000::\/49/)).toBeTruthy(),
    );
    expect(screen.queryByText("No allocation data")).toBeNull();
    const el = screen.getByLabelText(/fd71:a7:0:8000::\/49/) as HTMLElement;
    expect(el.style.left).toBe("50%");
    expect(el.style.width).toBe("50%");
  });

  it("the Treemap weighs the half-block child like the free space", async () => {
    wrap(
      <FreeSpaceTreemap
        block={block}
        directSubnets={[]}
        childBlocks={[child]}
      />,
    );
    await waitFor(() => expect(treemapData.length).toBe(3));
    const total = treemapData.reduce((a, c) => a + c.size, 0);
    const w = treemapData.find((c) => c.network === child.network)!;
    expect(w.size / total).toBeCloseTo(0.5, 5);
  });

  it("cidrSpan is exact past 2^53", () => {
    expect(cidrSpan("fd71:a7::/48")!.size).toBe(1n << 80n);
    expect(bigFraction(1n << 79n, 1n << 80n)).toBe(0.5);
    expect(cidrSpan("10.0.0.7/24")!.base).toBe(0x0a000000n);
  });
});
