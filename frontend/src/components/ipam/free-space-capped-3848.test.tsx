/**
 * @vitest-environment jsdom
 *
 * A capped free-space answer names the rest on its last range, and the Band
 * draws it as one free span with a note instead of leaving it blank (#3848).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { IPBlock } from "@/lib/api";

const free = [
  {
    network: "fd5e:1110:a:1940::/58",
    first: "",
    last: "",
    size: Number.MAX_SAFE_INTEGER,
    prefix_len: 58,
    more_after: 6,
  },
];

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    ipamApi: { ...actual.ipamApi, blockFreeSpace: async () => free },
  };
});

import { FreeSpaceBand } from "./FreeSpaceBand";

const block = { id: "b", network: "fd5e:1110:a::/48" } as IPBlock;

afterEach(cleanup);

describe("capped free-space answer (#3848)", () => {
  it("draws the rest of the block as one free span and says so", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <FreeSpaceBand
          block={block}
          directSubnets={[]}
          childBlocks={[]}
          onSelectFree={() => {}}
        />
      </QueryClientProvider>,
    );
    await waitFor(() =>
      expect(screen.getByText(/Showing 1 of 7 free ranges/)).toBeTruthy(),
    );
    const tail = screen.getByLabelText(/rest of the block after/);
    expect(tail.getAttribute("style")).toMatch(/width: 9[0-9]\./);
  });
});
