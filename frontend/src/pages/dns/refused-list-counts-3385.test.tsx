/**
 * @vitest-environment jsdom
 *
 * A count over a DNS list is the length of the list drawn under it (#3385,
 * the last line of #3337). A list the server refused, failed to send, or has
 * not sent yet has no length to draw: a server group's Zones tab read
 * "0 zones" over "You don't have permission to see this group's zones", a
 * zone's record list, a group's Records tab and its Blocking Lists tab drew
 * their counts the same way, and the group's Servers tab said "Zone serials:
 * no zones". Each draws no count until its list has loaded, and keeps the
 * count of a list that answered, empty or not.
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
const no = () => Promise.reject(refused());
const broken = () => Promise.reject(failed());
const waiting = () => new Promise(() => {});

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

const { DNSPage, ZoneDetailView } = await import("@/pages/dns/DNSPage");

function open(page: React.ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{page}</MemoryRouter>
    </QueryClientProvider>,
  );
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

const group = { id: "g1", name: "grp1", description: "" };
const zone = {
  id: "z1",
  group_id: "g1",
  name: "example.com.",
  zone_type: "primary",
  kind: "forward",
};

// The count lines as they read: "3 zones", "1 / 3 zones", "Records (3)",
// "3 records", "2 of 3 records", "3 blocking lists", and the Servers tab's
// "Zone serials: 3 zones · in sync on 1 server" ("no zones" for none).
const ZONE_COUNT = /^[\d,]+( \/ [\d,]+)? zones?$/;
const RECORDS_TAB_COUNT = /^Records \([\d,]+\)$/;
const RECORD_COUNT = /^[\d,]+ records?\b/;
const GROUP_RECORD_COUNT = /^[\d,]+ of [\d,]+ records?$/;
const BLOCKING_LIST_COUNT = /^[\d,]+ blocking lists?$/;
const ZONE_SERIALS = /^Zone serials: /;

// The text of the count line a pattern names, or null when none is drawn:
// a failure then shows the count that was drawn.
function drawn(count: RegExp): string | null {
  return screen.queryByText(count)?.textContent ?? null;
}

async function openGroupTab(tab: RegExp) {
  open(<DNSPage />);
  fireEvent.click(await screen.findByText("grp1"));
  fireEvent.click(await screen.findByRole("button", { name: tab }));
}

describe("a server group's Zones tab", () => {
  const dnsApi = { listGroups: ok([group]), listServers: ok([]) };

  it("draws no count over zones it was refused", async () => {
    answers.dnsApi = { ...dnsApi, listZones: no, listViews: ok([]) };
    await openGroupTab(/^Zones/);
    // The zone tree and the tab both say so.
    await waitFor(() =>
      expect(
        screen.getAllByText(/don't have permission to see this group's zones/)
          .length,
      ).toBe(2),
    );
    expect(drawn(ZONE_COUNT)).toBeNull();
  });

  it("draws no count over zones it failed to load", async () => {
    answers.dnsApi = { ...dnsApi, listZones: broken, listViews: ok([]) };
    await openGroupTab(/^Zones/);
    await waitFor(() =>
      expect(
        screen.getAllByText(/Couldn't load this group's zones/).length,
      ).toBe(2),
    );
    expect(drawn(ZONE_COUNT)).toBeNull();
  });

  it("draws no count while its zones are still loading", async () => {
    answers.dnsApi = { ...dnsApi, listZones: waiting, listViews: ok([]) };
    await openGroupTab(/^Zones/);
    await screen.findByRole("button", { name: /Export All/ });
    expect(drawn(ZONE_COUNT)).toBeNull();
  });

  it("still counts a zone list that answered empty", async () => {
    answers.dnsApi = { ...dnsApi, listZones: ok([]), listViews: ok([]) };
    await openGroupTab(/^Zones/);
    await screen.findByText(/No zones yet/);
    expect(screen.getByText(ZONE_COUNT).textContent).toBe("0 zones");
  });
});

describe("a zone's record list", () => {
  function openZone() {
    open(
      <ZoneDetailView
        group={group as never}
        zone={zone as never}
        onDeleted={() => {}}
      />,
    );
  }

  it("draws no count over records it was refused", async () => {
    answers.dnsApi = { listRecords: no };
    openZone();
    await screen.findByText(/don't have permission to see this zone's records/);
    expect(drawn(RECORDS_TAB_COUNT)).toBeNull();
    expect(screen.getByRole("button", { name: "Records" })).toBeTruthy();
    expect(drawn(RECORD_COUNT)).toBeNull();
  });

  it("draws no count over records it failed to load", async () => {
    answers.dnsApi = { listRecords: broken };
    openZone();
    await screen.findByText(/Couldn't load this zone's records/);
    expect(drawn(RECORDS_TAB_COUNT)).toBeNull();
    expect(drawn(RECORD_COUNT)).toBeNull();
  });

  it("still counts a record list that answered empty", async () => {
    answers.dnsApi = { listRecords: ok({ items: [], total: 0 }) };
    openZone();
    await screen.findByText(/No records yet/);
    expect(screen.getByText(RECORDS_TAB_COUNT).textContent).toBe("Records (0)");
    expect(screen.getByText(RECORD_COUNT).textContent).toBe("0 records");
  });
});

describe("a server group's Records tab", () => {
  const dnsApi = {
    listGroups: ok([group]),
    listServers: ok([]),
    listZones: ok([]),
    listViews: ok([]),
  };

  it("draws no count over records it was refused", async () => {
    answers.dnsApi = { ...dnsApi, listGroupRecords: no };
    await openGroupTab(/^Records/);
    await screen.findByText(
      /don't have permission to see this group's records/,
    );
    expect(drawn(GROUP_RECORD_COUNT)).toBeNull();
  });

  it("still counts a record list that answered empty", async () => {
    answers.dnsApi = {
      ...dnsApi,
      listGroupRecords: ok({ items: [], total: 0 }),
    };
    await openGroupTab(/^Records/);
    await screen.findByText("No records in this group yet.");
    expect(screen.getByText(GROUP_RECORD_COUNT).textContent).toBe(
      "0 of 0 records",
    );
  });
});

describe("a server group's Blocking Lists tab", () => {
  const dnsApi = {
    listGroups: ok([group]),
    listServers: ok([]),
    listZones: ok([]),
    listViews: ok([]),
  };

  it("draws no count over blocking lists it was refused", async () => {
    answers.dnsApi = dnsApi;
    answers.dnsBlocklistApi = { list: no };
    await openGroupTab(/^Blocking Lists/);
    await screen.findByText(/don't have permission to see blocking lists/);
    expect(drawn(BLOCKING_LIST_COUNT)).toBeNull();
  });

  it("still counts a blocking list read that answered empty", async () => {
    answers.dnsApi = dnsApi;
    answers.dnsBlocklistApi = { list: ok([]) };
    await openGroupTab(/^Blocking Lists/);
    await waitFor(() =>
      expect(screen.getByText(BLOCKING_LIST_COUNT).textContent).toBe(
        "0 blocking lists",
      ),
    );
  });
});

describe("a server group's Servers tab", () => {
  const server = {
    id: "s1",
    group_id: "g1",
    name: "ns1",
    driver: "bind9",
    host: "192.0.2.53",
    port: 53,
    status: "active",
    is_primary: true,
    is_enabled: true,
    roles: [],
  };
  const dnsApi = {
    listGroups: ok([group]),
    listServers: ok([server]),
    listViews: ok([]),
  };

  it("draws no zone serials line over zones it was refused", async () => {
    answers.dnsApi = { ...dnsApi, listZones: no };
    await openGroupTab(/^Servers/);
    await screen.findByText("ns1");
    // The zone tree says the zones were refused: the zones read has answered.
    await screen.findByText(/don't have permission to see this group's zones/);
    expect(drawn(ZONE_SERIALS)).toBeNull();
  });

  it("still says a group whose zone list answered empty has none", async () => {
    answers.dnsApi = { ...dnsApi, listZones: ok([]) };
    await openGroupTab(/^Servers/);
    await screen.findByText("ns1");
    await waitFor(() =>
      expect(drawn(ZONE_SERIALS)).toBe("Zone serials: no zones"),
    );
  });
});
