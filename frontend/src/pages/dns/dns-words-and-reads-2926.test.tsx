/**
 * @vitest-environment jsdom
 *
 * The DNS page's words and reads (#2926, #2927).
 *
 * #2926 — Add Zone filled its Linked Domain select from `GET /domains`
 * whatever the user's grants. The route needs read on `manage_domains` (the
 * IPAM / DNS / DHCP Editor roles lack it) and sits behind the
 * `network.domains` module (404 when off), so every opening was refused. The
 * read is now asked only when it can be answered; otherwise the select is
 * disabled with a note. Editing a zone that is already linked must keep the
 * link: the dialog sends the stored `domain_id` back, never null.
 *
 * #2927 — a disabled server is not paused: the zone sync pill counts the two
 * apart, and the server detail says "no (disabled)".
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
import type {
  DNSServer,
  DNSZone,
  ZoneServerState,
  ZoneServerStateEntry,
} from "@/lib/api";

const listDomains = vi.fn(() =>
  Promise.resolve({
    items: [{ id: "dom-1", name: "example.com", registrar: null }],
    total: 1,
  }),
);
const updateZone = vi.fn(
  (_groupId: string, zoneId: string, data: Record<string, unknown>) =>
    Promise.resolve({ id: zoneId, ...data }),
);
const createZone = vi.fn((_groupId: string, data: Record<string, unknown>) =>
  Promise.resolve({ id: "zone-new", ...data }),
);
const pending = () => new Promise<never>(() => {});

let grants: Array<[string, string]> = [];
let modulesReady = true;
let domainsModuleOn = true;

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: (action: string, resourceType: string) =>
        grants.some(([a, r]) => a === action && r === resourceType),
      isSuperadmin: false,
      isLoading: false,
    }),
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    ready: modulesReady,
    enabled: (id: string) =>
      !modulesReady || id !== "network.domains" || domainsModuleOn,
  }),
}));

let listedZones: unknown[] = [];

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      classifyZoneName: pending,
      listGroups: () => Promise.resolve([]),
      listZones: () => Promise.resolve(listedZones),
      getZoneDnssecInfo: pending,
      listDnssecPolicies: pending,
      createZone: (groupId: string, data: Record<string, unknown>) =>
        createZone(groupId, data),
      updateZone: (
        groupId: string,
        zoneId: string,
        data: Record<string, unknown>,
      ) => updateZone(groupId, zoneId, data),
      getServerRndcStatus: pending,
      getServerZoneState: pending,
      getServerPendingOps: pending,
      getServerRecentEvents: pending,
      getServerRenderedConfig: pending,
    },
    domainsApi: { ...actual.domainsApi, list: () => listDomains() },
    customersApi: { ...actual.customersApi, list: pending },
  };
});

const { ZoneModal, ZoneSyncPill } = await import("./DNSPage");
const { ServerDetailModal } = await import("./ServerDetailModal");

function wrap(node: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>);
}

function control(label: string): HTMLSelectElement {
  return screen.getByText(label, { selector: "label" })
    .nextElementSibling as HTMLSelectElement;
}

const linkedSelect = () => control("Linked Domain (optional)");

function linkedZone(domainId: string | null): DNSZone {
  return {
    id: "zone-1",
    group_id: "grp-1",
    view_id: null,
    name: "example.com.",
    zone_type: "primary",
    kind: "forward",
    ttl: 3600,
    primary_ns: "",
    admin_email: "",
    dnssec_enabled: false,
    color: null,
    forwarders: [],
    forward_only: true,
    masters: [],
    domain_id: domainId,
    customer_id: null,
  } as unknown as DNSZone;
}

function openZone(zone?: DNSZone) {
  listedZones = zone ? [zone] : [];
  wrap(<ZoneModal groupId="grp-1" views={[]} zone={zone} onClose={() => {}} />);
}

afterEach(() => {
  cleanup();
  grants = [];
  modulesReady = true;
  domainsModuleOn = true;
  listDomains.mockClear();
  updateZone.mockClear();
  createZone.mockClear();
});

describe("Add Zone's Linked Domain read (#2926)", () => {
  it("asks for the domain list when the user may read it", async () => {
    grants = [["read", "manage_domains"]];
    openZone();
    await waitFor(() => expect(listDomains).toHaveBeenCalledTimes(1));
    expect(linkedSelect().disabled).toBe(false);
    await screen.findByRole("option", { name: "example.com" });
  });

  it("does not ask without read on manage_domains, and says why", async () => {
    grants = [
      ["read", "dns_zone"],
      ["write", "dns_zone"],
    ];
    openZone();
    // Give a query every chance to fire.
    await new Promise((r) => setTimeout(r, 20));
    expect(listDomains).not.toHaveBeenCalled();
    expect(linkedSelect().disabled).toBe(true);
    expect(
      screen.getByText(/domain list is not available to your account/),
    ).toBeTruthy();
  });

  it("does not ask with the network.domains module off", async () => {
    grants = [["read", "manage_domains"]];
    domainsModuleOn = false;
    openZone();
    await new Promise((r) => setTimeout(r, 20));
    expect(listDomains).not.toHaveBeenCalled();
    expect(linkedSelect().disabled).toBe(true);
    expect(screen.getByText(/Domain tracking is turned off/)).toBeTruthy();
  });

  it("does not ask before the module state is known", async () => {
    grants = [["read", "manage_domains"]];
    modulesReady = false;
    openZone();
    await new Promise((r) => setTimeout(r, 20));
    expect(listDomains).not.toHaveBeenCalled();
  });

  it("keeps an existing link when an editor without the grant saves", async () => {
    grants = [
      ["read", "dns_zone"],
      ["write", "dns_zone"],
    ];
    openZone(linkedZone("dom-1"));
    await screen.findByText("Zone Name (FQDN)");
    // Shown as linked, not as "auto-match".
    expect(linkedSelect().value).toBe("dom-1");
    expect(
      screen.getByRole("option", { name: "Linked to a domain (kept as is)" }),
    ).toBeTruthy();
    fireEvent.change(screen.getByPlaceholderText("3600"), {
      target: { value: "600" },
    });
    fireEvent.submit(linkedSelect().form!);
    await waitFor(() => expect(updateZone).toHaveBeenCalledTimes(1));
    // Only the changed field is sent (#3269), so the link is left as stored.
    expect(updateZone.mock.calls[0][2]).toEqual({ ttl: 600 });
    expect(listDomains).not.toHaveBeenCalled();
  });

  it("sends no link for a new zone from an editor without the grant", async () => {
    grants = [["write", "dns_zone"]];
    openZone();
    fireEvent.change(control("Zone Name (FQDN)"), {
      target: { value: "corp.example.test" },
    });
    fireEvent.submit(linkedSelect().form!);
    await waitFor(() => expect(createZone).toHaveBeenCalledTimes(1));
    expect(createZone.mock.calls[0][1]).toMatchObject({ domain_id: null });
  });
});

function entry(
  name: string,
  freshness: ZoneServerStateEntry["freshness"],
): ZoneServerStateEntry {
  return {
    server_id: name,
    server_name: name,
    server_status: "active",
    current_serial: 42,
    reported_at: null,
    pending_ops: 0,
    freshness,
    counted: freshness === "ok",
  };
}

function pill(servers: ZoneServerStateEntry[]) {
  const state: ZoneServerState = {
    zone_id: "z",
    zone_name: "example.com.",
    target_serial: 42,
    servers,
    in_sync: true,
  };
  const { container } = wrap(<ZoneSyncPill state={state} />);
  return container.textContent ?? "";
}

describe("the zone sync pill counts paused and disabled apart (#2927)", () => {
  it("names a disabled server disabled, not paused", () => {
    const text = pill([entry("ns1", "ok"), entry("ns2", "disabled")]);
    expect(text).toContain("1 disabled");
    expect(text).not.toContain("paused");
  });

  it("lists both when there is one of each", () => {
    const text = pill([
      entry("ns1", "ok"),
      entry("ns2", "paused"),
      entry("ns3", "disabled"),
    ]);
    expect(text).toContain("1 paused · 1 disabled");
  });

  it("with no counted server, still names each", () => {
    expect(pill([entry("ns2", "disabled")])).toContain("1 disabled");
    cleanup();
    expect(pill([entry("ns2", "paused")])).toContain("1 paused");
  });
});

describe("a disabled server's detail (#2927)", () => {
  it('reads "no (disabled)", not "no (paused)"', () => {
    const server = {
      id: "s1",
      group_id: "g1",
      name: "ns1",
      driver: "bind9",
      roles: [],
      host: "192.0.2.53",
      port: 53,
      is_primary: false,
      is_enabled: false,
      maintenance_mode: false,
      status: "active",
    } as unknown as DNSServer;
    wrap(<ServerDetailModal server={server} onClose={() => {}} />);
    expect(screen.getByText("no (disabled)")).toBeTruthy();
    expect(screen.queryByText("no (paused)")).toBeNull();
  });
});
