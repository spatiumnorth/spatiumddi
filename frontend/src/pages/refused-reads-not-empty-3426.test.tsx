/**
 * @vitest-environment jsdom
 *
 * The reads #3343 did not reach (#3426, #3337's class). #3343 gave the DNS,
 * DHCP and IPAM lists it touched an error arm, so a refused or failed read
 * says so in place of an empty list. Six more took `data: x = []` (or a
 * `?? 0` total) and no error, so a read that was refused, failed or had not
 * answered drew as an empty list, with a zero count where there is one: a
 * zone's Pools tab, a group's TSIG Keys, ACLs and Views tabs, a blocking
 * list's entries and exceptions, and the DHCP sidebar's servers. A role that
 * reads DNS zones but not `manage_dns_pools` (the built-in Auditor) met the
 * first refused, and met the same refusal on the DNS Pools page, which the
 * sidebar offers to every DNS reader and which read every pool the same way.
 *
 * Each case answers ONE read with a 403 or a 500 and waits until that query
 * has failed, then requires no zero count, no empty state, and the refusal or
 * the failure said in words, as ListReadError says it. A read that has not
 * answered draws neither a count nor an empty state (#3385's rule for counts),
 * and a list that answered empty still says so, with its zero count.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};

function refused() {
  return Object.assign(new Error("Request failed with status code 403"), {
    isAxiosError: true,
    response: { status: 403, data: { detail: "Permission denied" } },
  });
}
function failed() {
  return Object.assign(new Error("Request failed with status code 500"), {
    isAxiosError: true,
    response: { status: 500, data: { detail: "database unavailable" } },
  });
}
const ok = (v: unknown) => () => Promise.resolve(v);
const waiting = () => new Promise(() => {});
const answer = {
  403: () => Promise.reject(refused()),
  500: () => Promise.reject(failed()),
};
// How the one read under test answers: refused, failed, never, or with an
// empty list (`empty`, in the shape that read answers in).
type Mode = 403 | 500 | "waiting" | "empty";
function reply(mode: Mode, empty: unknown): Answer {
  if (mode === "waiting") return waiting;
  if (mode === "empty") return ok(empty);
  return answer[mode];
}

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

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: false,
      isLoading: false,
    }),
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { DNSPage, ZoneDetailView, BlocklistDetail } =
  await import("@/pages/dns/DNSPage");
const { DHCPPage } = await import("@/pages/dhcp/DHCPPage");
const { DNSPoolsPage } = await import("@/pages/dns/DNSPoolsPage");

function open(page: React.ReactElement): QueryClient {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{page}</MemoryRouter>
    </QueryClientProvider>,
  );
  return client;
}

afterEach(() => {
  cleanup();
  for (const k of Object.keys(answers)) delete answers[k];
  try {
    sessionStorage.clear();
  } catch {
    // jsdom without storage: nothing was kept to clear.
  }
});

// Until the query behind the list has failed, an empty list proves nothing.
async function readFailed(client: QueryClient, key: string) {
  await waitFor(
    () =>
      expect(
        client
          .getQueryCache()
          .findAll({ queryKey: [key] })
          .some((q) => q.state.status === "error"),
      ).toBe(true),
    { timeout: 5000 },
  );
}

// The words #3343's ListReadError uses: 403, then anything else.
const SAYS = {
  403: /don't have permission to see/,
  500: /Couldn't load/,
} as const;
const SAID_ANY = /don't have permission to see|Couldn't load/;

function drawn(re: RegExp): string | null {
  return screen.queryAllByText(re)[0]?.textContent ?? null;
}

const group = { id: "g1", name: "grp1", description: "" };
const zone = {
  id: "z1",
  group_id: "g1",
  name: "example.com.",
  zone_type: "primary",
  kind: "forward",
};
const blockingList = {
  id: "bl1",
  name: "ads",
  description: "",
  category: "ads",
  source_type: "manual",
  feed_url: null,
  feed_format: "hosts",
  update_interval_hours: 24,
  block_mode: "nxdomain",
  sinkhole_ip: null,
  feed_entries_are_wildcard: false,
  enabled: true,
  last_synced_at: null,
  last_sync_status: null,
  last_sync_error: null,
  entry_count: 12,
  feed_parse_skipped: null,
};
const dnsGroupReads = {
  listGroups: ok([group]),
  listServers: ok([]),
  listZones: ok([]),
};

async function openGroupTab(tab: RegExp): Promise<QueryClient> {
  const client = open(<DNSPage />);
  fireEvent.click(await screen.findByText("grp1"));
  fireEvent.click(await screen.findByRole("button", { name: tab }));
  return client;
}

/**
 * One of the reads. `open` renders the page with that read answered as
 * `mode` says and reaches the list; `reached` waits for something the list's own
 * view always draws, so a read that never answers is looked at only once the
 * view is up. `count` reads the zero count the view would draw (null when it
 * has none), `empties` are its empty states, `emptyCount` is the count a list
 * that answered empty still draws, and `keys` are the queries that must have
 * failed (one per read the view makes of this list).
 */
type Site = {
  name: string;
  keys: string[];
  open: (mode: Mode) => Promise<QueryClient>;
  reach?: () => Promise<void>;
  reached: () => Promise<unknown>;
  count: () => string | null;
  empties: RegExp[];
  emptyCount: string | null;
};

const SITES: Site[] = [
  {
    name: "a zone's Pools tab",
    keys: ["dns-pools"],
    open: async (mode) => {
      answers.dnsApi = { listPools: reply(mode, []) };
      return open(
        <ZoneDetailView
          group={group as never}
          zone={zone as never}
          onDeleted={() => {}}
        />,
      );
    },
    // The tab label counts the pools; the Pools view, once opened, lists them.
    reach: async () => {
      fireEvent.click(await screen.findByRole("button", { name: /^Pools/ }));
    },
    reached: () => screen.findByText("Pools (GSLB-lite)"),
    count: () => drawn(/^Pools \(\d+\)$/),
    empties: [/^No pools/],
    emptyCount: "Pools (0)",
  },
  {
    name: "a group's TSIG Keys tab",
    keys: ["dns-tsig-keys"],
    open: (mode) => {
      answers.dnsApi = {
        ...dnsGroupReads,
        listViews: ok([]),
        listTSIGKeys: reply(mode, []),
      };
      return openGroupTab(/^TSIG Keys/);
    },
    reached: () => screen.findByText(/^Named TSIG keys distributed/),
    count: () => drawn(/^\d+ TSIG keys?$/),
    empties: [/^No TSIG keys yet/],
    emptyCount: "0 TSIG keys",
  },
  {
    name: "a group's ACLs tab",
    keys: ["dns-acls"],
    open: (mode) => {
      answers.dnsApi = {
        ...dnsGroupReads,
        listViews: ok([]),
        listAcls: reply(mode, []),
      };
      return openGroupTab(/^ACLs/);
    },
    reached: () => screen.findByText("Named ACLs"),
    count: () => null,
    empties: [/^No named ACLs defined/],
    emptyCount: null,
  },
  {
    name: "a group's Views tab",
    keys: ["dns-views"],
    open: (mode) => {
      answers.dnsApi = { ...dnsGroupReads, listViews: reply(mode, []) };
      answers.dnsBlocklistApi = { list: ok([]) };
      return openGroupTab(/^Views/);
    },
    reached: () => screen.findByRole("button", { name: /New View/ }),
    count: () => null,
    empties: [/^No views defined/],
    emptyCount: null,
  },
  {
    name: "a blocking list's entries and exceptions",
    keys: ["dns-blocklist-entries", "dns-blocklist-exceptions"],
    open: async (mode) => {
      answers.dnsBlocklistApi = {
        listEntries: reply(mode, { items: [], total: 0 }),
        listExceptions: reply(mode, []),
      };
      return open(
        <BlocklistDetail list={blockingList as never} onBack={() => {}} />,
      );
    },
    reached: () => screen.findByRole("heading", { name: "ads" }),
    // "12 entries · 3 exceptions", or either half alone.
    count: () => drawn(/^\d+ (entries|exceptions)\b/),
    empties: [/^No entries$/, /^No exceptions$/],
    emptyCount: "0 entries · 0 exceptions",
  },
  {
    name: "the DHCP sidebar's servers of a group",
    keys: ["dhcp-servers"],
    open: async (mode) => {
      answers.dhcpApi = {
        listGroups: ok([{ id: "dg1", name: "dhcp1", description: "" }]),
        listServers: reply(mode, []),
      };
      return open(<DHCPPage />);
    },
    // The count is drawn beside the group's name; its servers, once expanded.
    reach: async () => {
      await screen.findByText("dhcp1");
      fireEvent.click(screen.getByTitle("Expand"));
    },
    reached: () => screen.findByTitle("Collapse"),
    count: () => {
      const row = screen.queryByText("dhcp1")?.closest("button");
      return row
        ? (within(row).queryAllByText(/^\d+$/)[0]?.textContent ?? null)
        : null;
    },
    empties: [/^No servers in this group/],
    emptyCount: "0",
  },
  {
    // Not one of the issue's six: the same pools read, on the page the
    // sidebar offers every DNS reader, found in the sibling sweep.
    name: "the DNS Pools page",
    keys: ["dns-pools-all"],
    open: async (mode) => {
      answers.dnsApi = { listAllPools: reply(mode, []) };
      return open(<DNSPoolsPage />);
    },
    reached: () => screen.findByRole("heading", { name: "DNS Pools" }),
    count: () => null,
    empties: [/^No DNS pools yet/],
    emptyCount: null,
  },
];

// What the page drew for the read: its zero count, its empty states, and the
// lines that say a read was refused or failed.
function seen(site: Site, says: RegExp) {
  return {
    count: site.count(),
    emptyStates: site.empties.map(drawn).filter((t): t is string => t !== null),
    says: screen
      .queryAllByText(says)
      .map((e) => e.textContent)
      .filter((t): t is string => t !== null),
  };
}

async function reachAfter(site: Site, mode: Mode, settle?: string[]) {
  const client = await site.open(mode);
  for (const key of settle ?? []) await readFailed(client, key);
  await site.reach?.();
  for (const key of settle ?? []) await readFailed(client, key);
  await site.reached();
}

// The control: a list #3343 reached passes these same checks on main.
describe.each([403, 500] as const)("control, a read answered %i", (status) => {
  it("the DHCP server group list (#3343)", async () => {
    answers.dhcpApi = { listGroups: answer[status], listServers: ok([]) };
    const client = open(<DHCPPage />);
    await readFailed(client, "dhcp-groups");
    await waitFor(() =>
      expect({
        emptyStates: [drawn(/^No server groups yet/)].filter(Boolean),
        says: drawn(SAYS[status]),
      }).toEqual({
        emptyStates: [],
        says: expect.stringMatching(SAYS[status]),
      }),
    );
  });
});

describe.each([403, 500] as const)("a read answered %i", (status) => {
  it.each(SITES.map((s) => [s.name, s] as const))("%s", async (_name, site) => {
    await reachAfter(site, status, site.keys);
    await waitFor(() =>
      expect(seen(site, SAYS[status])).toEqual({
        count: null,
        emptyStates: [],
        says: site.keys.map(() => expect.stringMatching(SAYS[status])),
      }),
    );
  });
});

describe("a read that has not answered", () => {
  it.each(SITES.map((s) => [s.name, s] as const))(
    "%s draws no count and no empty state",
    async (_name, site) => {
      await reachAfter(site, "waiting");
      expect(seen(site, SAID_ANY)).toEqual({
        count: null,
        emptyStates: [],
        says: [],
      });
    },
  );
});

describe("a list that answered empty", () => {
  it.each(SITES.map((s) => [s.name, s] as const))(
    "%s still says so",
    async (_name, site) => {
      await reachAfter(site, "empty");
      await waitFor(() =>
        expect(seen(site, SAID_ANY)).toEqual({
          count: site.emptyCount,
          emptyStates: site.empties.map(() => expect.any(String)),
          says: [],
        }),
      );
    },
  );
});
