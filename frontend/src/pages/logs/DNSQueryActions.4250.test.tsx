/**
 * @vitest-environment jsdom
 *
 * DNS query details actions (#4250): Block / Allow domain, the "Blocked by"
 * line, the client panel and the More menu, each with its disabled reason.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, useLocation } from "react-router-dom";
import type {
  AgentLogSource,
  BlocklistMatch,
  DNSBlockList,
  DNSQueryLogRow,
} from "@/lib/api";

const GROUP = "g-1";
const VIEW = "v-1";

// Grants the fake user holds; ``unanswered`` models permissions still loading.
const grants = { set: new Set<string>(), unanswered: null as string | null };
const can = (action: string, type: string) =>
  grants.set.has(`${action}:${type}`);

const api = {
  match: vi.fn(),
  list: vi.fn(),
  addEntry: vi.fn(),
  deleteEntry: vi.fn(),
  addException: vi.fn(),
  deleteException: vi.fn(),
  listViews: vi.fn(),
  listGroups: vi.fn(),
  listZones: vi.fn(),
  searchAddresses: vi.fn(),
  findLeases: vi.fn(),
};

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can,
      hasAnyGrantFor: can,
      isSuperadmin: false,
      isLoading: false,
      isError: false,
      unanswered: grants.unanswered,
    }),
  };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    enabled: () => true,
    ready: true,
    modules: [],
    isLoading: false,
    isError: false,
    refetch: vi.fn(),
  }),
}));
vi.mock("@/components/copilot/useAiAvailable", () => ({
  useAiAvailable: () => false,
}));
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsBlocklistApi: {
      ...actual.dnsBlocklistApi,
      match: (...a: unknown[]) => api.match(...a),
      list: (...a: unknown[]) => api.list(...a),
      addEntry: (...a: unknown[]) => api.addEntry(...a),
      deleteEntry: (...a: unknown[]) => api.deleteEntry(...a),
      addException: (...a: unknown[]) => api.addException(...a),
      deleteException: (...a: unknown[]) => api.deleteException(...a),
    },
    dnsApi: {
      ...actual.dnsApi,
      listViews: (...a: unknown[]) => api.listViews(...a),
      listGroups: (...a: unknown[]) => api.listGroups(...a),
      listZones: (...a: unknown[]) => api.listZones(...a),
    },
    ipamApi: {
      ...actual.ipamApi,
      searchAddresses: (...a: unknown[]) => api.searchAddresses(...a),
    },
    dhcpApi: {
      ...actual.dhcpApi,
      findLeases: (...a: unknown[]) => api.findLeases(...a),
    },
  };
});

const { DNSQueryRow } = await import("../LogsPage");

const source = (over: Partial<AgentLogSource> = {}): AgentLogSource => ({
  server_id: "s-1",
  server_name: "ns1",
  server_kind: "dns",
  driver: "bind9",
  host: "10.0.0.53",
  group_id: GROUP,
  group_name: "dns-internal",
  ...over,
});

const row = (over: Partial<DNSQueryLogRow> = {}): DNSQueryLogRow => ({
  id: 1,
  ts: "2026-11-15T09:12:44Z",
  server_id: "s-1",
  server_name: "ns1",
  client_ip: "10.20.4.31",
  client_port: 52114,
  qname: "ads.tracker.example.com",
  qclass: "IN",
  qtype: "A",
  flags: "+E(0)",
  view: "guest",
  rcode: "NXDOMAIN",
  answer_count: 0,
  raw: "raw",
  ...over,
});

const manualList: DNSBlockList = {
  id: "l-1",
  name: "Local blocks",
  description: "",
  category: "custom",
  source_type: "manual",
  feed_url: null,
  feed_format: "domains",
  update_interval_hours: 0,
  block_mode: "nxdomain",
  sinkhole_ip: null,
  feed_wildcard_mode: "always",
  enabled: true,
  last_synced_at: null,
  last_sync_status: null,
  last_sync_error: null,
  entry_count: 0,
  feed_parse_skipped: null,
  created_at: "",
  modified_at: "",
  applied_group_ids: [GROUP],
  applied_view_ids: [],
};

const none: BlocklistMatch = {
  domain: "ads.tracker.example.com",
  effective: "none",
  matches: [],
  exceptions: [],
};

const hit = (over: Record<string, unknown> = {}) => ({
  list_id: "l-feed",
  list_name: "Ad feed",
  source_type: "url",
  block_mode: "nxdomain",
  sinkhole_ip: null,
  enabled: true,
  entry_id: "e-1",
  entry_domain: "example.com",
  is_wildcard: true,
  entry_source: "feed",
  entry_type: "block",
  target: null,
  reason: "",
  applies_here: true,
  excepted: false,
  ...over,
});

function Probe() {
  const l = useLocation();
  return <div data-testid="loc">{l.pathname + l.search}</div>;
}

function show(r: DNSQueryLogRow = row(), src: AgentLogSource = source()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <DNSQueryRow row={r} sources={[src]} onFilterClient={vi.fn()} />
        <Probe />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(screen.getByRole("button", { name: "Show row details" }));
}

const grant = (...g: string[]) => {
  grants.set = new Set(g);
};
const ALL = [
  "read:dns_blocklist",
  "write:dns_blocklist",
  "delete:dns_blocklist",
  "read:dns_group",
  "read:dns_zone",
  "read:use_network_tools",
  "read:ip_address",
  "read:dhcp_server",
];

beforeEach(() => {
  grants.unanswered = null;
  grant(...ALL);
  api.match.mockResolvedValue(none);
  api.list.mockResolvedValue([manualList]);
  api.listViews.mockResolvedValue([{ id: VIEW, name: "guest" }]);
  api.listGroups.mockResolvedValue([{ id: GROUP, name: "dns-internal" }]);
  api.listZones.mockResolvedValue([]);
  api.searchAddresses.mockResolvedValue({ items: [] });
  api.findLeases.mockResolvedValue({ items: [] });
  api.addEntry.mockResolvedValue({
    id: "new-entry",
    domain: "ads.tracker.example.com",
    is_wildcard: true,
  });
  api.deleteEntry.mockResolvedValue({});
  api.addException.mockResolvedValue({ id: "new-exc", domain: "x" });
  api.deleteException.mockResolvedValue({});
});
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const blockButton = () =>
  screen.findByRole("button", { name: /Block domain…/ });

async function enabledBlock() {
  const b = await blockButton();
  await waitFor(() => expect(b.getAttribute("aria-disabled")).toBe("false"));
  return b;
}

describe("Block domain", () => {
  it("states what changes and posts the entry, then Undo deletes it", async () => {
    show();
    fireEvent.click(await enabledBlock());
    const dlg = await screen.findByText("Block domain");
    expect(dlg).toBeTruthy();
    // The list, scope and response are spelled out before the click.
    const effect = screen.getByTestId("block-effect").textContent!;
    expect(effect).toContain("ads.tracker.example.com and every subdomain");
    expect(effect).toContain("Local blocks");
    expect(effect).toContain("whole group dns-internal");
    expect(effect).toContain("NXDOMAIN");
    fireEvent.click(
      screen.getByRole("button", {
        name: "Block ads.tracker.example.com and subdomains",
      }),
    );
    await waitFor(() => expect(api.addEntry).toHaveBeenCalled());
    expect(api.addEntry).toHaveBeenCalledWith("l-1", {
      domain: "ads.tracker.example.com",
      entry_type: "block",
      is_wildcard: true,
      reason: "Blocked from query log: client 10.20.4.31, 2026-11-15T09:12:44Z",
    });
    const undo = await screen.findByRole("button", { name: "Undo" });
    await act(async () => {
      fireEvent.click(undo);
    });
    await waitFor(() =>
      expect(api.deleteEntry).toHaveBeenCalledWith("l-1", "new-entry"),
    );
    expect((await screen.findByRole("status")).textContent).toContain("Undone");
  });

  it("blocks a parent as an exact name, with a shared-suffix warning", async () => {
    show();
    fireEvent.click(await enabledBlock());
    await screen.findByText("Block domain");
    fireEvent.click(screen.getByLabelText("example.com"));
    expect(screen.getByText(/not a shared suffix/)).toBeTruthy();
    fireEvent.click(screen.getByLabelText("This exact name only"));
    fireEvent.click(screen.getByRole("button", { name: "Block example.com" }));
    await waitFor(() =>
      expect(api.addEntry).toHaveBeenCalledWith(
        "l-1",
        expect.objectContaining({ domain: "example.com", is_wildcard: false }),
      ),
    );
  });

  it("resolves the row's view and asks for it", async () => {
    show();
    await waitFor(() =>
      expect(api.match).toHaveBeenCalledWith({
        domain: "ads.tracker.example.com",
        group_id: GROUP,
        view_id: VIEW,
      }),
    );
  });

  it("reports a 409 as already in the list", async () => {
    api.addEntry.mockRejectedValue({ response: { status: 409, data: {} } });
    show();
    fireEvent.click(await enabledBlock());
    await screen.findByText("Block domain");
    fireEvent.click(
      screen.getByRole("button", {
        name: "Block ads.tracker.example.com and subdomains",
      }),
    );
    expect((await screen.findByRole("alert")).textContent).toContain(
      "Already in Local blocks",
    );
  });
});

describe("Allow domain", () => {
  it("replaces Block for a blocked name, says by which list, and adds an exception", async () => {
    api.match.mockResolvedValue({
      ...none,
      effective: "blocked",
      matches: [hit()],
    });
    show();
    expect(
      await screen.findByRole("button", { name: /Allow domain…/ }),
    ).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Block domain…/ })).toBeNull();
    const by = await screen.findByTestId("blocked-by");
    expect(by.textContent).toContain("Blocked by Ad feed");
    expect(by.textContent).toContain("example.com");
    expect(by.textContent).toContain("wildcard");

    await waitFor(() =>
      expect(
        screen
          .getByRole("button", { name: /Allow domain…/ })
          .getAttribute("aria-disabled"),
      ).toBe("false"),
    );
    fireEvent.click(screen.getByRole("button", { name: /Allow domain…/ }));
    await screen.findByText("Allow domain", { selector: "h2" });
    // A feed entry cannot be deleted away: only the exception is offered, and
    // the text says the parent entry keeps blocking the rest.
    expect(screen.queryByLabelText("Remove the block entry")).toBeNull();
    const effect = screen.getByTestId("allow-effect").textContent!;
    expect(effect).toContain("keeps blocking the rest");
    expect(effect).toContain("every blocking list in the same group or view");
    fireEvent.click(
      screen.getByRole("button", { name: "Allow ads.tracker.example.com" }),
    );
    await waitFor(() =>
      expect(api.addException).toHaveBeenCalledWith("l-feed", {
        domain: "ads.tracker.example.com",
        reason:
          "Allowed from query log: client 10.20.4.31, 2026-11-15T09:12:44Z",
      }),
    );
    await act(async () => {
      fireEvent.click(await screen.findByRole("button", { name: "Undo" }));
    });
    await waitFor(() =>
      expect(api.deleteException).toHaveBeenCalledWith("l-feed", "new-exc"),
    );
  });

  it("removes a hand-made exact entry, and Undo puts it back", async () => {
    api.match.mockResolvedValue({
      ...none,
      effective: "blocked",
      matches: [
        hit({
          list_id: "l-1",
          list_name: "Local blocks",
          entry_id: "e-9",
          entry_domain: "ads.tracker.example.com",
          is_wildcard: false,
          entry_source: "manual",
          reason: "mine",
        }),
      ],
    });
    show();
    await waitFor(() =>
      expect(
        screen
          .getByRole("button", { name: /Allow domain…/ })
          .getAttribute("aria-disabled"),
      ).toBe("false"),
    );
    fireEvent.click(screen.getByRole("button", { name: /Allow domain…/ }));
    await screen.findByText("Allow domain", { selector: "h2" });
    expect(
      (screen.getByLabelText("Remove the block entry") as HTMLInputElement)
        .checked,
    ).toBe(true);
    fireEvent.click(
      screen.getByRole("button", { name: "Allow ads.tracker.example.com" }),
    );
    await waitFor(() =>
      expect(api.deleteEntry).toHaveBeenCalledWith("l-1", "e-9"),
    );
    await act(async () => {
      fireEvent.click(await screen.findByRole("button", { name: "Undo" }));
    });
    await waitFor(() =>
      expect(api.addEntry).toHaveBeenCalledWith(
        "l-1",
        expect.objectContaining({
          domain: "ads.tracker.example.com",
          is_wildcard: false,
          reason: "mine",
        }),
      ),
    );
  });

  it("shows an exception-allowed name as allowed, with Block still on offer", async () => {
    api.match.mockResolvedValue({
      ...none,
      effective: "allowed",
      matches: [hit({ excepted: true })],
    });
    show();
    expect((await screen.findByTestId("blocked-by")).textContent).toContain(
      "allowed by an exception",
    );
    expect(await blockButton()).toBeTruthy();
  });

  it("says NXDOMAIN is not from a blocking list when no list matches", async () => {
    show();
    expect(
      await screen.findByText(
        "NXDOMAIN came from DNS, not from a blocking list.",
      ),
    ).toBeTruthy();
  });
});

describe("disabled reasons", () => {
  const reasonShown = async (text: string | RegExp) => {
    const b = await blockButton();
    // The reason arrives with the lists; until then the button is pending.
    await waitFor(() => expect(b.getAttribute("title")).toMatch(text));
    expect(b.getAttribute("aria-disabled")).toBe("true");
    expect(
      document.getElementById(b.getAttribute("aria-describedby")!)!.textContent,
    ).toMatch(text);
    fireEvent.click(b);
    expect(screen.queryByText("Block domain")).toBeNull();
  };

  it("without write on blocklists", async () => {
    grant(...ALL.filter((g) => g !== "write:dns_blocklist"));
    show();
    await reasonShown("Needs write on DNS blocklists.");
  });

  it("hides Block and the Blocked-by line without read on blocklists", async () => {
    grant("read:dns_group");
    api.match.mockResolvedValue({
      ...none,
      effective: "blocked",
      matches: [hit()],
    });
    show();
    await screen.findByText("DNS query details");
    expect(screen.queryByRole("button", { name: /Block domain…/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Allow domain…/ })).toBeNull();
    expect(screen.queryByTestId("blocked-by")).toBeNull();
    expect(api.match).not.toHaveBeenCalled();
  });

  it("stays disabled, with no reason, while permissions load", async () => {
    grant();
    grants.unanswered = "Checking your permissions…";
    show();
    const b = await blockButton();
    expect(b.getAttribute("aria-disabled")).toBe("true");
    expect(b.getAttribute("title")).toBeNull();
  });

  it("for a name that cannot be blocked", async () => {
    show(row({ qname: "localhost" }));
    await reasonShown("This name cannot be blocked.");
  });

  it("for a reverse name", async () => {
    show(row({ qname: "4.3.2.10.in-addr.arpa" }));
    await reasonShown("This name cannot be blocked.");
  });

  it("for a driver that does not apply blocking lists", async () => {
    show(row(), source({ driver: "powerdns" }));
    await reasonShown("Blocking lists are not applied by powerdns servers.");
  });

  it("when no manual list applies to the group", async () => {
    api.list.mockResolvedValue([
      { ...manualList, applied_group_ids: ["other"] },
    ]);
    show();
    await reasonShown(/No manual blocking list is applied to dns-internal/);
  });

  it("when the row's server group is unknown", async () => {
    show(row({ server_id: "unknown" }));
    await reasonShown(
      "Cannot tell which DNS server group answered this query.",
    );
  });

  it("shows Block client disabled, with why", async () => {
    show();
    fireEvent.click(await screen.findByRole("button", { name: /More/ }));
    const item = screen.getByRole("menuitem", { name: /Block client/ });
    expect((item as HTMLButtonElement).disabled).toBe(true);
    expect(item.textContent).toContain("cannot block one client's DNS yet");
  });
});

describe("More menu", () => {
  it("opens the zone that serves the name, longest suffix first", async () => {
    api.listZones.mockResolvedValue([
      { id: "z-short", name: "com." },
      { id: "z-long", name: "example.com." },
    ]);
    show();
    fireEvent.click(await screen.findByRole("button", { name: /More/ }));
    const open = screen.getByRole("menuitem", { name: /Open zone/ });
    await waitFor(() =>
      expect((open as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(open);
    expect(screen.getByTestId("loc").textContent).toBe(
      `/dns?group=${GROUP}&zone=z-long`,
    );
  });

  it("says when no zone serves the name", async () => {
    show();
    fireEvent.click(await screen.findByRole("button", { name: /More/ }));
    await waitFor(() =>
      expect(
        screen.getByRole("menuitem", { name: /Open zone/ }).textContent,
      ).toContain("Not in a zone this group serves."),
    );
  });

  it("prefills dig with the name, type and the server's address", async () => {
    show();
    fireEvent.click(await screen.findByRole("button", { name: /More/ }));
    fireEvent.click(screen.getByRole("menuitem", { name: /dig this name/ }));
    expect(screen.getByTestId("loc").textContent).toBe(
      "/tools/network?tool=dig&name=ads.tracker.example.com&type=A&server=10.0.0.53",
    );
  });

  it("disables dig and whois without network-tools access", async () => {
    grant(...ALL.filter((g) => g !== "read:use_network_tools"));
    show();
    fireEvent.click(await screen.findByRole("button", { name: /More/ }));
    const dig = screen.getByRole("menuitem", { name: /dig this name/ });
    expect((dig as HTMLButtonElement).disabled).toBe(true);
    expect(dig.textContent).toContain("Needs access to network tools.");
  });
});

describe("client panel", () => {
  it("shows the IPAM address and the active lease, each linked", async () => {
    api.searchAddresses.mockResolvedValue({
      items: [
        {
          id: "a-1",
          subnet_id: "sn-1",
          address: "10.20.4.31",
          status: "allocated",
          hostname: "laptop-jsmith",
          subnet_name: "Guest",
          subnet_cidr: "10.20.0.0/16",
        },
        // A substring hit that is not this client.
        {
          id: "a-2",
          subnet_id: "sn-1",
          address: "10.20.4.311",
          hostname: "nope",
        },
      ],
    });
    api.findLeases.mockResolvedValue({
      items: [
        {
          server_id: "dhcp-1",
          mac_address: "aa:bb:cc:dd:ee:ff",
          hostname: "jsmith-phone",
          vendor: "Apple",
          device_class: "Phone",
          state: "active",
        },
      ],
    });
    show();
    const ipam = await screen.findByTestId("client-ipam");
    expect(ipam.textContent).toContain("laptop-jsmith");
    expect(ipam.textContent).not.toContain("nope");
    expect(
      within(ipam).getByRole("link", { name: "Open in IPAM" }),
    ).toBeTruthy();
    const lease = await screen.findByTestId("client-lease");
    expect(lease.textContent).toContain("aa:bb:cc:dd:ee:ff");
    expect(lease.textContent).toContain("Apple");
    expect(
      within(lease)
        .getByRole("link", { name: "Open DHCP server" })
        .getAttribute("href"),
    ).toBe("/dhcp?server=dhcp-1");
    expect(api.findLeases).toHaveBeenCalledWith({
      ip: "10.20.4.31",
      state: "active",
      page_size: 1,
    });
  });

  it("omits a section the viewer cannot read, and never asks for it", async () => {
    grant(...ALL.filter((g) => g !== "read:dhcp_server"));
    show();
    await screen.findByTestId("client-ipam");
    expect(screen.queryByTestId("client-lease")).toBeNull();
    expect(api.findLeases).not.toHaveBeenCalled();
  });

  it("omits IPAM without read on addresses", async () => {
    grant(...ALL.filter((g) => g !== "read:ip_address"));
    show();
    await screen.findByTestId("client-lease");
    expect(screen.queryByTestId("client-ipam")).toBeNull();
    expect(api.searchAddresses).not.toHaveBeenCalled();
  });

  it("says so when both are out of reach", async () => {
    grant(
      ...ALL.filter((g) => g !== "read:ip_address" && g !== "read:dhcp_server"),
    );
    show();
    expect(
      await screen.findByText("You do not have access to IPAM or DHCP data."),
    ).toBeTruthy();
  });

  it("reports a client in neither", async () => {
    show();
    expect(await screen.findByText("Not in IPAM")).toBeTruthy();
    expect(await screen.findByText("No active lease")).toBeTruthy();
  });
});
