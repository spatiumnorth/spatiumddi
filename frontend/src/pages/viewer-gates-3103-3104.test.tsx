/**
 * @vitest-environment jsdom
 *
 * Write controls a read-only Viewer must not be offered (#3103, #3104).
 *
 * #3103: Enter in a blocklist's "Domain to block" was a second path to the
 * Add button's POST, around its permission gate. #3104: the ASN BGP
 * Monitoring tab, the Looking Glass peer rows and the UniFi controller's own
 * page carried no gate at all. Real `usePermissions`, answered from
 * `GET /auth/me/permissions`.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import type { ReactNode } from "react";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};

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

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const STAMP = "2026-10-22T00:00:00Z";
const VIEWER: [string, string][] = [["read", "*"]];
type Grants = [string, string][] | "superadmin";

function signInAs(grants: Grants) {
  answers.authApi = {
    myPermissions: () =>
      Promise.resolve(
        grants === "superadmin"
          ? { is_superadmin: true, grants: [] }
          : {
              is_superadmin: false,
              grants: grants.map(([action, resource_type]) => ({
                action,
                resource_type,
                resource_id: null,
              })),
            },
      ),
  };
}

async function show(ui: ReactNode, path: string, route: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path={route} element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Let the permission answer land: every gate is closed while it loads. */
async function settled() {
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
}

function expectDenied(el: HTMLElement, reason: string) {
  const b = el as HTMLButtonElement;
  expect(b.disabled, `${b.title || b.textContent} is offered`).toBe(true);
  expect(b.title).toBe(reason);
}
function expectOffered(el: HTMLElement) {
  expect((el as HTMLButtonElement).disabled).toBe(false);
}
const byName = (n: string | RegExp) => screen.getByRole("button", { name: n });

/** A gated icon button is named by its tooltip, so while it is denied the
 *  reason is its name. Every button carrying that reason is disabled; an
 *  enabled icon button is found by its own title instead. */
function expectIconsDenied(reason: string, count: number) {
  const found = screen.getAllByTitle(reason) as HTMLButtonElement[];
  expect(found.length).toBe(count);
  for (const b of found) expect(b.disabled).toBe(true);
}

const BLOCKLIST = {
  id: "bl-1",
  name: "manual",
  description: "",
  category: "custom",
  source_type: "manual",
  feed_url: null,
  feed_format: "domains",
  update_interval_hours: 24,
  block_mode: "nxdomain",
  sinkhole_ip: null,
  feed_entries_are_wildcard: true,
  enabled: true,
  last_synced_at: null,
  last_sync_status: null,
  last_sync_error: null,
  entry_count: 0,
  feed_parse_skipped: null,
  created_at: STAMP,
  modified_at: STAMP,
  applied_group_ids: [],
  applied_view_ids: [],
};

describe("a blocklist's Domain to block (#3103)", () => {
  async function open(g: Grants, addEntry: Answer) {
    signInAs(g);
    answers.dnsBlocklistApi = {
      listEntries: () => Promise.resolve({ total: 0, items: [] }),
      listExceptions: () => Promise.resolve([]),
      addEntry,
    };
    const { BlocklistDetail } = await import("./dns/DNSPage");
    await show(
      <BlocklistDetail list={BLOCKLIST as never} onBack={() => {}} />,
      "/",
      "/",
    );
    await settled();
  }

  it("sends nothing on Enter for a Viewer, in either input", async () => {
    const add = vi.fn(() => Promise.resolve({}));
    await open(VIEWER, add);
    // The first Add is the entries form's; the exceptions form has its own.
    expectDenied(
      screen.getAllByRole("button", { name: /^Add$/ })[0],
      "Requires write permission on DNS blocklists",
    );
    const domain = screen.getByPlaceholderText("Domain to block");
    fireEvent.change(domain, { target: { value: "bad.example" } });
    fireEvent.keyDown(domain, { key: "Enter" });
    fireEvent.keyDown(screen.getAllByPlaceholderText("Reason (optional)")[0], {
      key: "Enter",
    });
    await settled();
    expect(add).not.toHaveBeenCalled();
  });

  it("still adds on Enter for a user who may write", async () => {
    const add = vi.fn(() => Promise.resolve({}));
    await open("superadmin", add);
    const domain = screen.getByPlaceholderText("Domain to block");
    fireEvent.change(domain, { target: { value: "bad.example" } });
    fireEvent.keyDown(domain, { key: "Enter" });
    await settled();
    expect(add).toHaveBeenCalledTimes(1);
  });
});

// ── ASN BGP Monitoring ────────────────────────────────────────────────────

const TRACKED = {
  id: "tp-1",
  asn_id: "asn-1",
  prefix: "203.0.113.0/24",
  expected_origin_asn: 64512,
  source: "manual",
  enabled: true,
  allowed_origins: [],
  last_seen_origins: null,
  last_checked_at: null,
  next_check_at: null,
};
const HIJACK = {
  id: "hj-1",
  asn_id: "asn-1",
  tracked_prefix_id: "tp-1",
  tracked_prefix: "203.0.113.0/24",
  observed_prefix: "203.0.113.0/24",
  expected_origin_asn: 64512,
  observed_origin_asn: 64666,
  detection_kind: "prefix_hijack",
  rpki_status: "invalid",
  severity: "critical",
  source: "ripestat",
  first_seen_at: STAMP,
  last_seen_at: STAMP,
  resolved_at: null,
  acknowledged: false,
  detail: null,
  notes: "",
};

describe("an ASN's BGP Monitoring tab (#3104)", () => {
  async function open(g: Grants) {
    signInAs(g);
    answers.asnsApi = {
      listTrackedPrefixes: () => Promise.resolve([TRACKED]),
      listHijacks: () => Promise.resolve([HIJACK]),
    };
    const { BgpMonitorTab } = await import("./network/BgpMonitorTab");
    await show(<BgpMonitorTab asnId="asn-1" asnKind="public" />, "/", "/");
    await screen.findByText("AS64666", { exact: false });
    await settled();
  }

  it("offers a Viewer no write", async () => {
    await open(VIEWER);
    // Track prefix, Check BGP now, Acknowledge and Allowlist.
    expectIconsDenied("Requires write permission on ASNs", 4);
    expectIconsDenied("Requires delete permission on ASNs", 1);
    expectDenied(byName(/Track prefix/), "Requires write permission on ASNs");
  });

  it("offers an ASN manager every one", async () => {
    await open("superadmin");
    expectOffered(byName(/Track prefix/));
    expectOffered(byName(/Check BGP now/));
    expectOffered(byName("Acknowledge"));
    expectOffered(byName(/Allowlist/));
    expectOffered(byName("Stop tracking"));
  });
});

// ── Looking Glass peers ───────────────────────────────────────────────────

const LG_SESSION = {
  peer_id: "pr-1",
  peer_name: "edge-rtr",
  collector_id: "co-1",
  collector_name: "collector",
  collector_status: "online",
  local_asn: 64512,
  peer_asn: 64513,
  peer_address: "192.0.2.1",
  enabled: true,
  session_state: "established",
  uptime_started_at: null,
  prefixes_received: 0,
  prefixes_accepted: 0,
  last_state_change: null,
  last_flap_at: null,
  rpki_invalid_count: 0,
  down_since: null,
};
const LG_PEER = {
  ...LG_SESSION,
  id: "pr-1",
  name: "edge-rtr",
  collector_id: "co-1",
  matched_asn_id: null,
  peer_router_id: null,
  address_families: [],
  md5_password_set: false,
  max_prefixes: 0,
  import_filter: {},
  description: "",
  created_at: STAMP,
  modified_at: STAMP,
};

describe("a Looking Glass peer row (#3104)", () => {
  async function open(g: Grants) {
    signInAs(g);
    answers.lookingGlassApi = {
      listSessions: () => Promise.resolve([LG_SESSION]),
      listPeers: () => Promise.resolve([LG_PEER]),
    };
    const { SessionsTab } = await import("./network/looking-glass/SessionsTab");
    await show(
      <SessionsTab
        collectors={[{ id: "co-1" } as never]}
        onEdit={() => {}}
        onViewRoutes={() => {}}
      />,
      "/",
      "/",
    );
    await screen.findByText("edge-rtr");
    await settled();
  }

  it("offers a Viewer no Edit or Delete", async () => {
    await open(VIEWER);
    expectDenied(
      byName("Requires write permission on BGP peers"),
      "Requires write permission on BGP peers",
    );
    expectDenied(
      byName("Requires delete permission on BGP peers"),
      "Requires delete permission on BGP peers",
    );
  });

  it("offers a superadmin both", async () => {
    await open("superadmin");
    expectOffered(byName("Edit peer"));
    expectOffered(byName("Delete peer"));
  });
});

// ── UniFi controller page ─────────────────────────────────────────────────

describe("a UniFi controller's own page (#3104)", () => {
  async function open(g: Grants) {
    signInAs(g);
    answers.unifiApi = {
      getDashboard: () =>
        Promise.resolve({
          controller: {
            id: "uc-1",
            name: "baseline-ctl",
            description: "",
            mode: "local",
            host: "192.0.2.5",
            port: 443,
            cloud_host_id: null,
            enabled: true,
            controller_version: null,
            site_allowlist: [],
            last_synced_at: null,
            last_sync_error: null,
          },
          subnets: [],
          vlans: [],
          clients: [],
        }),
    };
    const { UnifiControllerDetailPage } =
      await import("./unifi/UnifiControllerDetailPage");
    await show(<UnifiControllerDetailPage />, "/unifi/uc-1", "/unifi/:id");
    await screen.findByText("baseline-ctl", { selector: "h1" });
    await settled();
  }

  it("offers a Viewer no Test or Sync Now", async () => {
    await open(VIEWER);
    expectDenied(byName(/^Test$/), "Requires superadmin");
    expectDenied(byName(/Sync Now/), "Requires superadmin");
  });

  it("offers a superadmin both", async () => {
    await open("superadmin");
    expectOffered(byName("Test"));
    expectOffered(byName(/Sync Now/));
  });
});
