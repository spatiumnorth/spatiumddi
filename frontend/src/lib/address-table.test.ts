import { afterEach, describe, expect, it, vi } from "vitest";
import { api, type IPAddress } from "@/lib/api";
import {
  buildAddressTableRows,
  buildTableParams,
  fetchAddressTablePage,
  hasPageOnlyFilter,
  type TableFilterState,
} from "@/lib/address-table";

const row = (last: number, status = "allocated") =>
  ({
    id: `id${last}`,
    address: `10.0.0.${last}`,
    status,
  }) as unknown as IPAddress;

const state = (over: Partial<TableFilterState> = {}): TableFilterState => ({
  colFilters: {
    address: "",
    hostname: "",
    mac: "",
    description: "",
    tags: "",
    status: "",
    dns: "",
  },
  filterModes: {},
  tagChips: [],
  sort: null,
  ...over,
});

afterEach(() => vi.restoreAllMocks());

describe("buildTableParams (#1256)", () => {
  it("sends nothing for an untouched table", () => {
    expect(buildTableParams(state())).toEqual({});
  });

  it("maps column filters, modes, chips and sort to the server's params", () => {
    const s = state({
      colFilters: {
        ...state().colFilters,
        hostname: "^web",
        tags: "env",
        status: "reserved",
        dns: "in-sync",
      },
      filterModes: { hostname: "regex", tags: "begins", address: "ends" },
      tagChips: ["env:prod"],
      sort: { key: "last_seen", dir: "desc" },
    });
    expect(buildTableParams(s)).toEqual({
      hostname: "^web",
      tag_text: "env",
      status_filter: "reserved",
      tag: ["env:prod"],
      // address has a mode but no value: no match entry for it.
      match: ["hostname:regex", "tag_text:begins"],
      sort: "last_seen",
      order: "desc",
    });
  });

  it("leaves the browser-derived dns sort and filter to the page", () => {
    const s = state({
      colFilters: { ...state().colFilters, dns: "n/a" },
      sort: { key: "dns", dir: "asc" },
    });
    expect(buildTableParams(s)).toEqual({});
    expect(hasPageOnlyFilter(s)).toBe(true);
    expect(hasPageOnlyFilter(state())).toBe(false);
  });
});

describe("fetchAddressTablePage (#1256)", () => {
  function serve(total: number) {
    const calls: Record<string, unknown>[] = [];
    vi.spyOn(api, "get").mockImplementation(((
      _u: string,
      cfg: { params: { limit: number; offset: number } },
    ) => {
      calls.push(cfg.params);
      const { limit, offset } = cfg.params;
      const n = Math.max(0, Math.min(limit, total - offset));
      return Promise.resolve({
        data: Array.from({ length: n }, (_, i) => row(offset + i)),
        headers: { "x-total-count": String(total) },
      });
    }) as never);
    return calls;
  }

  it("reads only the first page, with the total", async () => {
    const calls = serve(5000);
    const page = await fetchAddressTablePage(
      "s1",
      { status_filter: "x" },
      0,
      100,
    );
    expect(calls).toEqual([{ status_filter: "x", limit: 100, offset: 0 }]);
    expect(page.rows).toHaveLength(100);
    expect(page.prev).toBeNull();
    expect(page.total).toBe(5000);
  });

  it("starts a later page one row early to learn the row before it", async () => {
    const calls = serve(5000);
    const page = await fetchAddressTablePage("s1", {}, 2, 100);
    expect(calls[0]).toMatchObject({ limit: 101, offset: 199 });
    expect(page.prev?.id).toBe("id199");
    expect(page.rows).toHaveLength(100);
    expect(page.rows[0].id).toBe("id200");
  });
});

describe("buildAddressTableRows (#1256)", () => {
  const base = {
    prev: null,
    isLastPage: true,
    sorted: false,
    pools: [],
    hasActiveFilter: false,
    hideReserved: false,
    hideFreeRanges: false,
  };
  const kinds = (r: ReturnType<typeof buildAddressTableRows>) =>
    r.map((x) =>
      x.kind === "ip"
        ? x.addr.address
        : x.kind === "gap"
          ? `gap`
          : `${x.boundary}:${x.pool.name}`,
    );

  it("marks a gap inside the page", () => {
    const rows = buildAddressTableRows({
      ...base,
      addresses: [row(1), row(5)],
    });
    expect(kinds(rows)).toEqual(["10.0.0.1", "gap", "10.0.0.5"]);
  });

  it("marks a gap at the top of a later page using the previous row", () => {
    const rows = buildAddressTableRows({
      ...base,
      prev: row(1),
      addresses: [row(5), row(6)],
    });
    expect(kinds(rows)).toEqual(["gap", "10.0.0.5", "10.0.0.6"]);
  });

  const pool = {
    id: "p1",
    name: "dyn",
    pool_type: "dynamic",
    start_ip: "10.0.0.10",
    end_ip: "10.0.0.20",
  };

  it("does not repeat a pool's markers on a later page", () => {
    // Page 2 begins past the pool, whose start and end page 1 already showed.
    const rows = buildAddressTableRows({
      ...base,
      prev: row(30),
      addresses: [row(31), row(32)],
      pools: [pool],
    });
    expect(kinds(rows)).toEqual(["10.0.0.31", "10.0.0.32"]);
  });

  it("shows a pool's end on the page it falls on, and only its end", () => {
    const rows = buildAddressTableRows({
      ...base,
      prev: row(15),
      addresses: [row(25)],
      pools: [pool],
    });
    expect(kinds(rows)).toEqual(["end:dyn", "10.0.0.25"]);
  });

  it("leaves unstarted pools to the last page", () => {
    const early = buildAddressTableRows({
      ...base,
      isLastPage: false,
      addresses: [row(1), row(2)],
      pools: [pool],
    });
    expect(kinds(early)).toEqual(["10.0.0.1", "10.0.0.2"]);
    const last = buildAddressTableRows({
      ...base,
      addresses: [row(1), row(2)],
      pools: [pool],
    });
    expect(kinds(last)).toEqual([
      "10.0.0.1",
      "10.0.0.2",
      "start:dyn",
      "end:dyn",
    ]);
  });

  it("is a plain list under a column sort, minus hidden network rows", () => {
    const rows = buildAddressTableRows({
      ...base,
      sorted: true,
      hideReserved: true,
      addresses: [row(9), row(0, "network"), row(3)],
      pools: [pool],
    });
    expect(kinds(rows)).toEqual(["10.0.0.9", "10.0.0.3"]);
  });
});
