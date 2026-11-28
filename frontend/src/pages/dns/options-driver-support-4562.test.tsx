/**
 * @vitest-environment jsdom
 *
 * The Options tab used to offer every option to every driver, and the API
 * stored what the driver then ignored (#4562). Which options a group's
 * drivers apply now comes from the API's per-driver table on the options
 * response (``option_support``): a control the driver does not apply is
 * disabled with the note, a stored value stays editable so it can be cleared,
 * and a driver that applies no option gets one line in place of the form.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const state = vi.hoisted(() => ({
  extra: {} as Record<string, unknown>,
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      getOptions: () =>
        Promise.resolve({
          forwarders: [],
          allow_query: [],
          allow_recursion: [],
          allow_transfer: [],
          rrl_exempt_clients: [],
          forward_policy: "first",
          forward_transport: "do53",
          dnssec_validation: "auto",
          trust_anchors: [],
          recursion_enabled: true,
          query_log_enabled: false,
          dot_port: 853,
          doh_port: 443,
          doq_port: 853,
          doh_path: "/dns-query",
          tls_certificate_id: null,
          ...state.extra,
        }),
      listServers: () => Promise.resolve([]),
      forwarderPresets: () => Promise.resolve({ version: "test", presets: [] }),
    },
    applianceTlsApi: {
      ...actual.applianceTlsApi,
      list: () => Promise.resolve([]),
    },
    versionApi: {
      get: () => Promise.resolve({ version: "test", appliance_mode: true }),
    },
  };
});

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: true,
      isLoading: false,
    }),
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { OptionsTab } = await import("@/pages/dns/DNSPage");

afterEach(() => {
  cleanup();
  state.extra = {};
});

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <OptionsTab groupId="grp-1" />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const PDNS = "PowerDNS authoritative does not recurse (there is no recursor)";

function recursionBox(): HTMLInputElement {
  return screen
    .getByText("Enable recursion")
    .parentElement!.querySelector("input") as HTMLInputElement;
}

function aclInput(): HTMLInputElement {
  return screen.getByPlaceholderText(/blank = default/) as HTMLInputElement;
}

describe("Options tab follows the API's per-driver table (#4562)", () => {
  it("disables what the driver does not apply, with the note", async () => {
    state.extra = {
      recursion_enabled: false,
      option_support: {
        recursion_enabled: {
          state: "not_applied",
          drivers: ["PowerDNS"],
          note: PDNS,
          locked: true,
        },
        allow_recursion: {
          state: "not_applied",
          drivers: ["PowerDNS"],
          note: PDNS,
          locked: true,
        },
      },
    };
    renderTab();
    expect(
      await screen.findByText(`This group has a PowerDNS server: ${PDNS}.`),
    ).toBeTruthy();
    expect(recursionBox().disabled).toBe(true);
    expect(aclInput().disabled).toBe(true);
  });

  it("keeps a stored value editable so it can be cleared", async () => {
    state.extra = {
      option_support: {
        recursion_enabled: {
          state: "not_applied",
          drivers: ["PowerDNS"],
          note: PDNS,
          locked: false,
        },
      },
    };
    renderTab();
    await screen.findByText(`This group has a PowerDNS server: ${PDNS}.`);
    expect(recursionBox().disabled).toBe(false);
  });

  it("leaves every control enabled when the table has no entry", async () => {
    renderTab();
    await screen.findByText("Enable recursion");
    expect(recursionBox().disabled).toBe(false);
    expect(aclInput().disabled).toBe(false);
    expect(screen.queryByText(/This group has a/)).toBeNull();
  });

  it("names the driver on the query-log card, not BIND", async () => {
    state.extra = {
      option_support: {
        query_log_enabled: {
          state: "not_applied",
          drivers: ["Technitium"],
          note: "query logging is not collected from Technitium servers yet",
          locked: true,
        },
      },
    };
    renderTab();
    expect(
      await screen.findByText(
        "This group has a Technitium server: query logging is not collected from Technitium servers yet.",
      ),
    ).toBeTruthy();
    expect(screen.queryByText(/received\s+by BIND/)).toBeNull();
  });

  it("shows one line in place of the form when the driver applies no option", async () => {
    state.extra = {
      options_unmanaged_note:
        "This group has a Windows DNS server, so the options here are not applied: SpatiumDDI writes zones and records to Windows DNS, not server settings; set it on the Windows server.",
    };
    renderTab();
    expect(
      await screen.findByText(/Windows DNS server, so the options/),
    ).toBeTruthy();
    expect(screen.queryByText("Enable recursion")).toBeNull();
    expect(screen.queryByText("Save Changes")).toBeNull();
  });

  it("lists stored values a driver does not apply", async () => {
    state.extra = {
      unapplied_warnings: [
        "PowerDNS does not apply allow_query: PowerDNS authoritative has no client query ACL",
      ],
    };
    renderTab();
    expect(
      await screen.findByText(/PowerDNS does not apply allow_query/),
    ).toBeTruthy();
  });
});
