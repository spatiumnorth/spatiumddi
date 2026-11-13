import { afterEach, describe, expect, it, vi } from "vitest";
import { ADDRESS_PAGE_SIZE, api, ipamApi, type IPAddress } from "@/lib/api";

const row = (i: number) =>
  ({ id: String(i), address: `10.0.0.${i}` }) as unknown as IPAddress;

function serve(total: number) {
  const calls: Record<string, string | number>[] = [];
  vi.spyOn(api, "get").mockImplementation(((
    _u: string,
    cfg: { params: { limit: number; offset?: number } },
  ) => {
    calls.push(cfg.params);
    const { limit, offset = 0 } = cfg.params;
    const n = Math.max(0, Math.min(limit, total - offset));
    return Promise.resolve({
      data: Array.from({ length: n }, (_, i) => row(offset + i)),
      headers: { "x-total-count": String(total) },
    });
  }) as never);
  return calls;
}

afterEach(() => vi.restoreAllMocks());

describe("ipamApi.listAddresses (#1256)", () => {
  it("reads a big subnet in pages instead of one unbounded call", async () => {
    const calls = serve(ADDRESS_PAGE_SIZE * 2 + 5);
    const rows = await ipamApi.listAddresses("s1");
    expect(rows).toHaveLength(ADDRESS_PAGE_SIZE * 2 + 5);
    expect(calls.map((c) => c.offset)).toEqual([
      0,
      ADDRESS_PAGE_SIZE,
      ADDRESS_PAGE_SIZE * 2,
    ]);
    expect(calls.every((c) => c.limit === ADDRESS_PAGE_SIZE)).toBe(true);
  });

  it("stops after one request when the total is an exact multiple", async () => {
    const calls = serve(ADDRESS_PAGE_SIZE);
    await ipamApi.listAddresses("s1");
    expect(calls).toHaveLength(1);
  });

  it("an explicit limit is a single windowed request, filters intact", async () => {
    const calls = serve(50);
    const rows = await ipamApi.listAddresses("s1", {
      status_filter: "network",
      limit: 1,
    });
    expect(rows).toHaveLength(1);
    expect(calls).toEqual([{ status_filter: "network", limit: 1 }]);
  });

  it("keeps filters on every page", async () => {
    const calls = serve(ADDRESS_PAGE_SIZE + 1);
    await ipamApi.listAddresses("s1", { status_filter: "orphan" });
    expect(calls.every((c) => c.status_filter === "orphan")).toBe(true);
  });
});
