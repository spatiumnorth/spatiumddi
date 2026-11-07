/**
 * @vitest-environment jsdom
 *
 * The free-space answer's `size` saturates at 2^63 - 1 for IPv6 (#3708). The
 * Treemap must not weigh free ranges by it, or every free range of /64 or
 * wider draws the same area.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { IPBlock } from "@/lib/api";

// What a JS client reads for the saturated 2^63 - 1.
const CAP = Number(BigInt(2) ** BigInt(63) - BigInt(1));
const free = [
  { network: "fd37:8:0:8000::/49", prefix_len: 49, exp: 79 },
  { network: "fd37:8:0:4000::/50", prefix_len: 50, exp: 78 },
].map(({ network, prefix_len, exp }) => ({
  network,
  first: "",
  last: "",
  size: CAP,
  size_exact: (BigInt(1) << BigInt(exp)).toString(),
  prefix_len,
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

import { FreeSpaceTreemap } from "./FreeSpaceTreemap";

afterEach(cleanup);

describe("FreeSpaceTreemap free-range weights (#3708)", () => {
  it("weighs a free /49 twice a free /50, not by the saturated size", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <FreeSpaceTreemap
          block={{ id: "b", network: "fd37:8::/48" } as IPBlock}
          directSubnets={[]}
          childBlocks={[]}
        />
      </QueryClientProvider>,
    );
    await waitFor(() => expect(treemapData.length).toBe(2));
    const w = (n: string) => treemapData.find((c) => c.network === n)!.size;
    expect(w("fd37:8:0:8000::/49") / w("fd37:8:0:4000::/50")).toBe(2);
  });
});
