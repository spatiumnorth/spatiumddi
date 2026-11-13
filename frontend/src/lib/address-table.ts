// Server-side paging for the IPAM subnet address table (#1256 part 2).
//
// The table used to load every row of a subnet and filter / sort / window in
// the browser. These helpers are the pure half of the replacement: they turn
// the table's filter + sort state into query params, read one page, and build
// the page's display rows (pool-boundary and gap markers) from that page plus
// the row just before it.

import { api, type AddressQueryParams, type IPAddress } from "@/lib/api";

export type FilterMode = "contains" | "begins" | "ends" | "regex";

export type PoolMeta = {
  id: string;
  name: string;
  pool_type: string;
  start_ip: string;
  end_ip: string;
  _start: number;
  _end: number;
};

export type AddressOrPoolRow =
  | { kind: "ip"; addr: IPAddress }
  | { kind: "pool-boundary"; pool: PoolMeta; boundary: "start" | "end" }
  // Visual marker between two non-adjacent rows (eg .10 and .12, showing .11
  // is unallocated). Skipped inside dynamic DHCP pools, whose gaps belong to
  // the DHCP server and are not operator-allocatable.
  | { kind: "gap"; startIpInt: number; endIpInt: number };

/** Page sizes the table offers. */
export const ADDRESS_TABLE_PAGE_SIZES = [100, 250, 500, 1000] as const;
export const ADDRESS_TABLE_DEFAULT_PAGE_SIZE = 500;

// IPv4-only: pool markers and gaps are IPv4-only, matching the old table.
export function ipStringToInt(ip: string): number {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255))
    return NaN;
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

export interface TableFilterState {
  colFilters: {
    address: string;
    hostname: string;
    mac: string;
    description: string;
    tags: string;
    status: string;
    dns: string;
  } & Record<string, string>;
  filterModes: Record<string, FilterMode>;
  tagChips: string[];
  sort: { key: string; dir: "asc" | "desc" } | null;
}

// Sort keys the server can order by. ``dns`` is derived in the browser from
// the drift report, so it only orders the page on screen.
const SERVER_SORT_KEYS = new Set([
  "address",
  "hostname",
  "mac",
  "description",
  "status",
  "last_seen",
]);

/** Query params for the server-side half of the table's filters + sort. */
export function buildTableParams(s: TableFilterState): AddressQueryParams {
  const cf = s.colFilters;
  const p: AddressQueryParams = {};
  if (cf.address) p.address = cf.address;
  if (cf.hostname) p.hostname = cf.hostname;
  if (cf.mac) p.mac = cf.mac;
  if (cf.description) p.description = cf.description;
  if (cf.tags) p.tag_text = cf.tags;
  if (cf.status) p.status_filter = cf.status;
  if (s.tagChips.length) p.tag = s.tagChips;
  const match: string[] = [];
  const fields: [string, string][] = [
    ["address", cf.address],
    ["hostname", cf.hostname],
    ["mac", cf.mac],
    ["description", cf.description],
    ["tag_text", cf.tags],
  ];
  for (const [field, value] of fields) {
    // The table calls the free-text tag filter "tags".
    const mode = s.filterModes[field === "tag_text" ? "tags" : field];
    if (value && mode && mode !== "contains") match.push(`${field}:${mode}`);
  }
  if (match.length) p.match = match;
  if (s.sort && SERVER_SORT_KEYS.has(s.sort.key)) {
    p.sort = s.sort.key as AddressQueryParams["sort"];
    p.order = s.sort.dir;
  }
  return p;
}

/** True when a filter is set that only the browser can apply (it is derived
 *  from the DNS drift report), and so narrows the loaded page, not the set. */
export function hasPageOnlyFilter(s: TableFilterState): boolean {
  return !!s.colFilters.dns;
}

export interface AddressTablePage {
  rows: IPAddress[];
  /** The row just before this page in the same order (null on page 0), so the
   *  page can place a gap or pool boundary that falls at its very top. */
  prev: IPAddress | null;
  /** Rows matching the server-side filters, across all pages. */
  total: number;
}

/** Read page ``pageIndex`` of the subnet's addresses. A page after the first
 *  starts one row early to learn ``prev``. */
export async function fetchAddressTablePage(
  subnetId: string,
  params: AddressQueryParams,
  pageIndex: number,
  pageSize: number,
): Promise<AddressTablePage> {
  const anchor = pageIndex > 0 ? 1 : 0;
  const r = await api.get<IPAddress[]>(`/ipam/subnets/${subnetId}/addresses`, {
    params: {
      ...params,
      limit: pageSize + anchor,
      offset: pageIndex * pageSize - anchor,
    },
  });
  const prev = anchor && r.data.length ? r.data[0] : null;
  const rows = anchor ? r.data.slice(1) : r.data;
  const hdr = Number(r.headers?.["x-total-count"] ?? NaN);
  const total = Number.isFinite(hdr) ? hdr : pageIndex * pageSize + rows.length;
  return { rows, prev, total };
}

interface BuildRowsArgs {
  addresses: IPAddress[];
  prev: IPAddress | null;
  isLastPage: boolean;
  /** A custom column sort is on: plain list, no markers. */
  sorted: boolean;
  pools: {
    id: string;
    name: string;
    pool_type: string;
    start_ip: string;
    end_ip: string;
  }[];
  hasActiveFilter: boolean;
  hideReserved: boolean;
  hideFreeRanges: boolean;
}

const isPadding = (a: { status: string }) =>
  a.status === "network" || a.status === "broadcast";

/** The page's display rows: IP rows interleaved with DHCP pool boundary
 *  markers and "N free" gap markers (inet order only). */
export function buildAddressTableRows(a: BuildRowsArgs): AddressOrPoolRow[] {
  const { addresses, hideReserved } = a;
  if (a.sorted) {
    const flat = addresses.map((addr) => ({ kind: "ip", addr }) as const);
    return hideReserved ? flat.filter((r) => !isPadding(r.addr)) : [...flat];
  }
  const rows: AddressOrPoolRow[] = [];
  const sortedPools: PoolMeta[] = a.pools
    .map((p) => ({
      ...p,
      _start: ipStringToInt(p.start_ip),
      _end: ipStringToInt(p.end_ip),
    }))
    .filter((p) => Number.isFinite(p._start) && Number.isFinite(p._end))
    .sort((x, y) => x._start - y._start);

  const started = new Set<string>();
  const ended = new Set<string>();

  // Emit every pool-boundary marker that resolves at or before ``ipInt``,
  // interleaved by the marker's own IP position, so two pools resolving at
  // the same crossing read START a, END a, START b, END b.
  const emitBoundariesUpTo = (ipInt: number) => {
    const events: {
      pos: number;
      pool: PoolMeta;
      boundary: "start" | "end";
    }[] = [];
    for (const p of sortedPools) {
      if (!started.has(p.id) && p._start <= ipInt)
        events.push({ pos: p._start, pool: p, boundary: "start" });
      if (!ended.has(p.id) && p._end < ipInt)
        events.push({ pos: p._end, pool: p, boundary: "end" });
    }
    events.sort((x, y) =>
      x.pos !== y.pos ? x.pos - y.pos : x.boundary === "end" ? -1 : 1,
    );
    for (const e of events) {
      rows.push({ kind: "pool-boundary", pool: e.pool, boundary: e.boundary });
      if (e.boundary === "start") started.add(e.pool.id);
      else ended.add(e.pool.id);
    }
  };

  // A gap fully inside a dynamic pool is DHCP-owned, not allocatable.
  const gapInsideDynamicPool = (s: number, e: number) =>
    sortedPools.some(
      (p) => p.pool_type === "dynamic" && p._start <= s && e <= p._end,
    );

  // A page after the first: the row before it has already been shown, along
  // with every marker up to it. Replay those silently so they are not shown
  // again, and so a gap or marker at this page's top still lands.
  let prevIpInt: number | null = null;
  if (a.prev) {
    const pi = ipStringToInt(String(a.prev.address));
    if (Number.isFinite(pi)) {
      emitBoundariesUpTo(pi);
      rows.length = 0;
      prevIpInt = pi;
    }
  }

  for (const addr of addresses) {
    const ipInt = ipStringToInt(String(addr.address));
    if (!Number.isFinite(ipInt)) {
      rows.push({ kind: "ip", addr });
      prevIpInt = null;
      continue;
    }
    emitBoundariesUpTo(ipInt);

    // Gaps are skipped when a pool boundary was just emitted, when the gap is
    // inside a dynamic pool, and whenever a filter is active: a filter that
    // hides allocated rows would fabricate a clickable "N free" range over
    // addresses in use (#501).
    if (
      !a.hasActiveFilter &&
      !a.hideFreeRanges &&
      prevIpInt !== null &&
      ipInt - prevIpInt > 1
    ) {
      const lastWasPool = rows[rows.length - 1]?.kind === "pool-boundary";
      const gapStart = prevIpInt + 1;
      const gapEnd = ipInt - 1;
      if (!lastWasPool && !gapInsideDynamicPool(gapStart, gapEnd))
        rows.push({ kind: "gap", startIpInt: gapStart, endIpInt: gapEnd });
    }

    rows.push({ kind: "ip", addr });
    prevIpInt = ipInt;
  }

  // Pools still open, and pools wholly past the last IP, close out on the
  // last page only; an earlier page leaves them to the page they fall on.
  if (a.isLastPage) {
    for (const p of sortedPools) {
      if (started.has(p.id) && !ended.has(p.id)) {
        rows.push({ kind: "pool-boundary", pool: p, boundary: "end" });
        ended.add(p.id);
      }
    }
    for (const p of sortedPools) {
      if (!started.has(p.id)) {
        rows.push({ kind: "pool-boundary", pool: p, boundary: "start" });
        rows.push({ kind: "pool-boundary", pool: p, boundary: "end" });
      }
    }
  }
  return hideReserved
    ? rows.filter((r) => r.kind !== "ip" || !isPadding(r.addr))
    : rows;
}
